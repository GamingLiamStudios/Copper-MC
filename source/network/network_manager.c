#include "network_manager.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <uniconv.h>
#include <unistdio.h>

#include <zlib-ng.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <curl/curl.h>
#include <json-c/json.h>

#include "server/server.h"
#include "logger/logger.h"
#include "util/containers/slotmap.h"
#include "util/containers/buffer.h"
#include "util/containers/queue.h"
#include "util/hexdump.h"

#include "varints.h"
#include "packets/packet_reader.h"
#include "packets/packet_builder.h"

// Config
// TODO: Move to runtime config
#define MAX_PLAYERS           20
#define PORT                  25565
#define COMPRESSION_THRESHOLD 256
#define ONLINE_MODE           1

struct network_manager
{
    socket_t       *socket;
    struct slotmap *clients;
    struct queue   *packet_queue;

    struct buffer *packet_buffer;
    struct buffer *compression_buffer;

    u64 *connected_players;
};

struct network_client
{
    socket_t socket;
    void    *cipher_key;
    enum
    {
        CLIENTSTATE_HANDSHAKE,
        CLIENTSTATE_STATUS,
        CLIENTSTATE_LOGIN,
        CLIENTSTATE_PLAY
    } state;
    enum
    {
        CLIENTPARAMS_COMPRESSED = 0b001,
        CLIENTPARAMS_ENCRYPTED  = 0b010,
        CLIENTPARAMS_VERSION    = 0b100
    } params;
};

struct login_encrypt_temp
{
    RSA *rsa;
    u8  *username;
    u8   verify[4];
};

struct encryption_keys
{
    EVP_CIPHER_CTX *enc;
    EVP_CIPHER_CTX *dec;
};

// These are 'signals'. They are used to modify the state of the client.
enum
{
    CLIENTSIGNAL_DISCONNECT,
    CLIENTSIGNAL_ENABLE_COMPRESSION,
    CLIENTSIGNAL_SWITCH_STATE
};

i32 _network_manager_compress_packet(
  struct buffer *packet_buffer,
  struct buffer *compression_buffer,
  struct packet *packet)
{
    i32 index = 0;
    // First, let's get a buffer of the data to compress
    buffer_append_u8(packet_buffer, packet->packet_id);
    buffer_append(packet_buffer, packet->data, packet->size);

    size_t data_length = 0;
    buffer_clear(compression_buffer);
    if ((packet->size + 1) >= COMPRESSION_THRESHOLD)
    {
        // Compress the packet
        buffer_reserve(compression_buffer, zng_compressBound(packet_buffer->size));

        data_length = compression_buffer->capacity;
        i32 ret     = zng_compress(
          compression_buffer->data,
          &data_length,
          packet_buffer->data,
          packet_buffer->size);
        if (ret != Z_OK)
        {
            logger_log_level(LOG_LEVEL_ERROR, "Error %d: Failed to compress packet!", ret);
            return -1;
        }

        compression_buffer->size = data_length;
        data_length              = packet_buffer->size;
    }
    else
        // Don't compress the packet
        buffer_append(compression_buffer, packet_buffer->data, packet_buffer->size);

    // Now, let's write the packet to the client
    buffer_clear(packet_buffer);
    packet_write_varint(
      packet_buffer,
      varint_size(data_length) + compression_buffer->size);    // Packet Length
    packet_write_varint(packet_buffer, data_length);           // Data Length
    packet_write_bytes(
      packet_buffer,
      compression_buffer->data,
      compression_buffer->size);    // Compressed Data(Packet ID + Data)

    return 0;
}

void _network_manager_destroy_client(struct network_client *client)
{
    if (!client) return;

    if (client->cipher_key)
    {
        if (client->params & CLIENTPARAMS_ENCRYPTED)
        {
            struct encryption_keys *ctx = client->cipher_key;

            if (ctx->enc)
            {
                u8  tmp[1];
                int len = 1;
                EVP_EncryptFinal_ex(ctx->enc, tmp, &len);
                EVP_CIPHER_CTX_free(ctx->enc);
                ctx->enc = NULL;
            }
            if (ctx->dec)
            {
                u8  tmp[1];
                int len = 1;
                EVP_DecryptFinal_ex(ctx->dec, tmp, &len);
                EVP_CIPHER_CTX_free(ctx->dec);
                ctx->dec = NULL;
            }

            free(ctx);
        }
        else
        {
            struct login_encrypt_temp *temp = client->cipher_key;

            RSA_free(temp->rsa);
            free(temp->username);
            free(temp);
        }
    }

    socket_destroy(client->socket);
    client->params     = 0;
    client->state      = 0;
    client->cipher_key = NULL;
    free(client);
}

void _network_manager_disconnect(
  struct slotmap *clients,
  struct buffer  *packet_buffer,
  struct buffer  *compression_buffer,
  u64            *connected_players,
  i32             client_id)
{
    struct network_client *client = slotmap_get(clients, client_id);

    struct packet packet;
    packet.packet_id = -1;
    switch (client->state)
    {
    case CLIENTSTATE_PLAY: packet.packet_id = 0x40; (*connected_players)--;
    case CLIENTSTATE_LOGIN:
        if (packet.packet_id == -1) packet.packet_id = 0x00;
        {
            i32 string_length = varint_decode(packet_buffer->data);
            if (string_length == 0)
            {
                const char *disconnect_message = "{\"text\":\"Server requested Disconnect\"}";
                string_length                  = strlen(disconnect_message);

                packet.size = string_length + varint_size(string_length);
                packet.data = malloc(packet.size);
                varint_encode(packet.data, string_length);
                memcpy(packet.data + varint_size(string_length), disconnect_message, string_length);
            }
            else
            {
                packet.size = string_length + varint_size(string_length);
                packet.data = malloc(string_length + varint_size(string_length));
                memcpy(
                  packet.data,
                  packet_buffer->data,
                  string_length + varint_size(string_length));
            }

            i32 index = 0;
            buffer_clear(packet_buffer);
            if (client->params & CLIENTPARAMS_COMPRESSED)
            {
                if (
                  _network_manager_compress_packet(packet_buffer, compression_buffer, &packet) < 0)
                {
                    free(packet.data);
                    pthread_exit(NULL);
                }
            }
            else
            {
                packet_write_varint(packet_buffer, packet.size);
                packet_write_varint(packet_buffer, packet.packet_id);
                packet_write_bytes(packet_buffer, packet.data, packet.size);
            }

            if (client->params & CLIENTPARAMS_ENCRYPTED)
            {
                struct encryption_keys *ctx = client->cipher_key;

                buffer_reserve(compression_buffer, packet_buffer->size);
                i32 len = compression_buffer->capacity;
                EVP_EncryptUpdate(
                  ctx->enc,
                  compression_buffer->data,
                  &len,
                  packet_buffer->data,
                  packet_buffer->size);

                i32 ret = socket_send(client->socket, compression_buffer->data, len);
                if (ret == SOCKET_ERROR) pthread_exit(NULL);
            }
            else
            {
                i32 ret = socket_send(client->socket, packet_buffer->data, packet_buffer->size);
                if (ret == SOCKET_ERROR) pthread_exit(NULL);
            }

            logger_log_level(LOG_LEVEL_DEBUG, "Client %d disconnected!", client_id);
        }
        break;
    default: break;
    }

    slotmap_remove(clients, client_id);
    _network_manager_destroy_client(client);
}

void _network_manager_cleanup(void *args)
{
    struct network_manager *manager = args;

    const char *disconnect_message = "{\"text\":\"Server shutting down\"}";
    buffer_clear(manager->packet_buffer);
    packet_write_string(manager->packet_buffer, (u8 *) disconnect_message);
    for (const struct slotmap_entry *itt = slotmap_end(manager->clients) - 1;
         itt >= slotmap_begin(manager->clients);
         itt--)
        _network_manager_disconnect(
          manager->clients,
          manager->packet_buffer,
          manager->compression_buffer,
          manager->connected_players,
          itt->key);

    slotmap_destroy(manager->clients);
    socket_destroy(*manager->socket);

    struct packet *packet;
    while ((packet = queue_pop(manager->packet_queue))) free(packet);
    queue_destroy(manager->packet_queue);

    buffer_destroy(manager->packet_buffer);
    buffer_destroy(manager->compression_buffer);

    free(manager->clients);
    free(manager->socket);
    free(manager->packet_queue);
    free(manager->packet_buffer);
    free(manager->compression_buffer);
    free(manager);

    logger_log("Closing Network Manager");
}

size_t _network_manager_curl_read(void *buffer, size_t size, size_t nmemb, void *userp)
{
    i32            real_size  = size * nmemb;
    struct buffer *buffer_ptr = userp;

    buffer_append(buffer_ptr, buffer, real_size);

    return real_size;
}

void _network_manager_process_packets(
  struct slotmap      *clients,
  struct queue        *packet_queue,
  struct packet_queue *packet_queues,
  struct buffer       *packet_buffer,
  struct buffer       *compression_buffer,
  u64                 *connected_players)
{
    struct queue *serverbound_packets = &packet_queues->serverbound;
    struct queue *clientbound_packets = &packet_queues->clientbound;

    struct packet       *packet = NULL;
    struct packet_reader reader = { 0 };

    while ((packet = queue_pop(packet_queue)))
    {
        struct network_client *client_data = slotmap_get(clients, packet->client_id);
        packet_reader_init(&reader, packet);

        switch (client_data->state)
        {
        case CLIENTSTATE_HANDSHAKE:
        {
            if (packet->packet_id > 0x00)
            {
                logger_log_level(LOG_LEVEL_ERROR, "Unknown Packet! ID: %2X", packet->packet_id);
                pthread_exit(NULL);
            }

            // Handshake
            i32       protocol_version = packet_next_varint(&reader);
            const u8 *hostname         = packet_next_string(&reader);
            u16       port             = packet_next_ushort(&reader);
            i32       next_state       = packet_next_varint(&reader);

            if (protocol_version == 754)
                client_data->params |=
                  CLIENTPARAMS_VERSION;    // Tell server we are using the same protocol version

            client_data->state = next_state;
            logger_log_level(
              LOG_LEVEL_DEBUG,
              "Handshaken with client %d into state %d",
              packet->client_id,
              next_state);
        }
        break;
        case CLIENTSTATE_STATUS:
        {
            // TODO: Implement Legacy Server List Ping
            switch (packet->packet_id)
            {
            case 0x00:
            {
                // Status Request
                struct packet *status_packet = malloc(sizeof(struct packet));
                status_packet->client_id     = packet->client_id;
                status_packet->packet_id     = 0x00;

                // TODO: Config description + Unicode support
                const char *status_format =
                  "{\"version\":{\"name\":\"1.16.5\",\"protocol\":754},\"players\":{\"max\":%d,"
                  "\"online\":%d,\"sample\":[]},\"description\":{\"text\":\"GLS' Copper-MC "
                  "Testing Server\"}}";
                i32 string_length =
                  snprintf(NULL, 0, status_format, MAX_PLAYERS, *connected_players);

                status_packet->size = varint_size(string_length) + string_length;
                status_packet->data = malloc(status_packet->size + 1);    // For Null-Terminator

                varint_encode(status_packet->data, string_length);
                snprintf(
                  (char *) status_packet->data + varint_size(string_length),
                  string_length + 1,
                  status_format,
                  MAX_PLAYERS,
                  *connected_players);

                queue_push(clientbound_packets, status_packet);
            }
            break;
            case 0x01:
            {
                // Status Ping
                struct packet *status_packet = malloc(sizeof(struct packet));
                status_packet->client_id     = packet->client_id;
                status_packet->packet_id     = packet->packet_id;

                status_packet->size = packet->size;
                status_packet->data = malloc(packet->size);
                memcpy(status_packet->data, packet->data, packet->size);
                queue_push(clientbound_packets, status_packet);

                struct packet *disconnect_signal = malloc(sizeof(struct packet));
                disconnect_signal->client_id     = packet->client_id;
                disconnect_signal->packet_id     = -1;    // Signal Packet

                disconnect_signal->size    = 1 + varint_size(0);
                disconnect_signal->data    = malloc(disconnect_signal->size);
                disconnect_signal->data[0] = CLIENTSIGNAL_DISCONNECT;
                varint_encode(disconnect_signal->data + 1, 0);
                queue_push(clientbound_packets, disconnect_signal);
            }
            break;
            default:
                logger_log_level(LOG_LEVEL_ERROR, "Unknown Packet! ID: %2X", packet->packet_id);
                pthread_exit(NULL);
            }
            break;
        }
        case CLIENTSTATE_LOGIN:
        {
            switch (packet->packet_id)
            {
            case 0x00:
            {
                // Check if Protocol Version is valid
                if (!(client_data->params & CLIENTPARAMS_VERSION))
                {
                    logger_log_level(
                      LOG_LEVEL_INFO,
                      "Client %d attempted connection with unsupported version",
                      packet->client_id);

                    // Send disconnect signal
                    buffer_clear(packet_buffer);
                    packet_write_string(
                      packet_buffer,
                      (u8 *) ("{\"text\":\"Attempted connection with unsupported version. Please "
                              "try again with version 1.16.5\"}"));
                    _network_manager_disconnect(
                      clients,
                      packet_buffer,
                      compression_buffer,
                      connected_players,
                      packet->client_id);
                    break;
                }

                // Login Start
                const u8 *username = packet_next_string(&reader);

                logger_log_level(
                  LOG_LEVEL_DEBUG,
                  "Client %d logged in as %U",
                  packet->client_id,
                  username);

                // Check if Local host
                struct sockaddr_in rem_addr, loc_addr;
                u32                len = sizeof(rem_addr);

                getpeername(client_data->socket, (struct sockaddr *) &rem_addr, &len);
                getsockname(client_data->socket, (struct sockaddr *) &loc_addr, &len);
                if (ONLINE_MODE /* && rem_addr.sin_addr.s_addr != loc_addr.sin_addr.s_addr */)
                {
                    // Generate RSA Keypair
                    RSA    *rsa = RSA_new();
                    BIGNUM *e   = BN_new();
                    BN_set_word(e, RSA_F4);
                    RSA_generate_key_ex(rsa, 1024, e, NULL);
                    BN_free(e);

                    // Encryption Request Packet
                    struct packet *client_packet = malloc(sizeof(struct packet));
                    client_packet->client_id     = packet->client_id;
                    client_packet->packet_id     = 0x01;

                    // Create BIO containing DER encoding
                    BIO *pub = BIO_new(BIO_s_mem());
                    i2d_RSA_PUBKEY_bio(pub, rsa);

                    i32 der_length      = BIO_pending(pub);
                    u8 *der_encoded_key = malloc(der_length);
                    BIO_read(pub, der_encoded_key, der_length);
                    BIO_free_all(pub);

                    buffer_clear(packet_buffer);

                    packet_write_varint(packet_buffer, 0);    // Server ID
                    packet_write_varint(packet_buffer, der_length);
                    packet_write_bytes(packet_buffer, der_encoded_key, der_length);
                    packet_write_varint(packet_buffer, 4);    // Verify Token Length
                    packet_write_byte(packet_buffer, rand() & 0xFF);
                    packet_write_byte(packet_buffer, rand() & 0xFF);
                    packet_write_byte(packet_buffer, rand() & 0xFF);
                    packet_write_byte(packet_buffer, rand() & 0xFF);

                    packet_builder_final(packet_buffer, client_packet);
                    free(der_encoded_key);

                    struct login_encrypt_temp *temp = malloc(sizeof(struct login_encrypt_temp));
                    temp->rsa                       = rsa;
                    temp->username                  = (u8 *) username;
                    memcpy(temp->verify, packet_buffer->data + packet_buffer->size - 4, 4);
                    client_data->cipher_key = temp;

                    queue_push(clientbound_packets, client_packet);
                }
                else
                {
                    // Generate Player UUID
                    const char *UUID_hash_format = "OfflinePlayer:";
                    u8         *UUID_hash_string =
                      malloc(strlen(UUID_hash_format) + strlen((const char *) username));
                    memcpy(UUID_hash_string, UUID_hash_format, strlen(UUID_hash_format));
                    memcpy(
                      UUID_hash_string + strlen(UUID_hash_format),
                      username,
                      strlen((const char *) username));

                    char *UUID = malloc(MD5_DIGEST_LENGTH);
                    MD5(
                      UUID_hash_string,
                      strlen(UUID_hash_format) + strlen((const char *) username),
                      (u8 *) UUID);
                    UUID[6] = (UUID[6] & 0x0f) | 0x30;
                    free(UUID_hash_string);

                    // Set Compression Packet
                    struct packet *client_packet = malloc(sizeof(struct packet));
                    client_packet->client_id     = packet->client_id;
                    client_packet->packet_id     = 0x03;
                    client_packet->size          = varint_size(COMPRESSION_THRESHOLD);
                    client_packet->data          = malloc(client_packet->size);
                    varint_encode(client_packet->data, COMPRESSION_THRESHOLD);
                    queue_push(clientbound_packets, client_packet);

                    // Update Client Parameters
                    client_packet            = malloc(sizeof(struct packet));
                    client_packet->client_id = packet->client_id;
                    client_packet->packet_id = -1;    // Signal Packet
                    client_packet->size      = 1;
                    client_packet->data      = malloc(client_packet->size);
                    client_packet->data[0]   = CLIENTSIGNAL_ENABLE_COMPRESSION;
                    queue_push(clientbound_packets, client_packet);

                    // Send Login Success
                    client_packet            = malloc(sizeof(struct packet));
                    client_packet->client_id = packet->client_id;
                    client_packet->packet_id = -2;    // Login Success bounce

                    buffer_clear(packet_buffer);
                    packet_write_uuid(packet_buffer, (u8 *) UUID);
                    packet_write_string(packet_buffer, username);
                    packet_builder_final(packet_buffer, client_packet);
                    free(UUID);

                    // Server will bounce this back to client
                    queue_push(serverbound_packets, client_packet);

                    // Update Client State
                    client_packet            = malloc(sizeof(struct packet));
                    client_packet->client_id = packet->client_id;
                    client_packet->packet_id = -1;    // Signal Packet
                    client_packet->size      = 2;
                    client_packet->data      = malloc(client_packet->size);
                    client_packet->data[0]   = CLIENTSIGNAL_SWITCH_STATE;
                    client_packet->data[1]   = CLIENTSTATE_PLAY;
                    queue_push(clientbound_packets, client_packet);

                    (*connected_players)++;
                    logger_log("%U has joined the Server.", username);
                    free((u8 *) username);
                }
            }
            break;
            case 0x01:
            {
                struct login_encrypt_temp *temp     = client_data->cipher_key;
                u8                        *username = temp->username;
                client_data->cipher_key             = NULL;

                // Encryption Response
                i32 enc_secret_length = varint_decode(packet->data);
                u8 *secret            = malloc(RSA_size(temp->rsa) - 11);
                i32 secret_length     = RSA_private_decrypt(
                  enc_secret_length,
                  packet->data + varint_size(enc_secret_length),
                  secret,
                  temp->rsa,
                  RSA_PKCS1_PADDING);

                // Verify packet
                i32 enc_verify_length =
                  varint_decode(packet->data + varint_size(enc_secret_length) + enc_secret_length);
                u8 *verify        = malloc(RSA_size(temp->rsa) - 11);
                i32 verify_length = RSA_private_decrypt(
                  enc_verify_length,
                  packet->data + varint_size(enc_secret_length) + enc_secret_length +
                    varint_size(enc_verify_length),
                  verify,
                  temp->rsa,
                  RSA_PKCS1_PADDING);

                if (CRYPTO_memcmp(verify, temp->verify, verify_length) != 0)
                {
                    logger_log_level(
                      LOG_LEVEL_WARN,
                      "Client %d[%U] failed to authenticate",
                      packet->client_id,
                      username);
                    logger_log_level(
                      LOG_LEVEL_DEBUG,
                      "Reason[%d]: verify mismatch.",
                      packet->client_id);
                    free(secret);
                    free(verify);

                    free(temp->username);
                    RSA_free(temp->rsa);
                    free(temp);

                    // Send disconnect signal
                    buffer_clear(packet_buffer);
                    packet_write_string(
                      packet_buffer,
                      (u8 *) ("{\"text\":\"Failed to verify client.\"}"));
                    _network_manager_disconnect(
                      clients,
                      packet_buffer,
                      compression_buffer,
                      connected_players,
                      packet->client_id);
                    break;
                }
                free(verify);

                // Compute 'identifier hash'
                SHA_CTX sha;
                SHA1_Init(&sha);
                SHA1_Update(&sha, secret, secret_length);

                BIO *pub = BIO_new(BIO_s_mem());
                i2d_RSA_PUBKEY_bio(pub, temp->rsa);

                i32 der_length     = BIO_pending(pub);
                u8 *der_public_key = malloc(der_length);
                BIO_read(pub, der_public_key, der_length);
                SHA1_Update(&sha, der_public_key, der_length);
                BIO_free_all(pub);

                u8 *hash = malloc(SHA_DIGEST_LENGTH);
                SHA1_Final(hash, &sha);
                free(der_public_key);

                // MC-style hex digest
                char *hash_string = malloc(1);
                hash_string[0]    = '\0';
                BIGNUM *bn        = BN_bin2bn(hash, SHA_DIGEST_LENGTH, NULL);
                if (BN_is_bit_set(bn, 159))
                {
                    // FIXME: Can cause memory leak if realloc fails
                    hash_string    = realloc(hash_string, 2);
                    hash_string[0] = '-';
                    hash_string[1] = '\0';

                    u8 *tmp = malloc(BN_num_bytes(bn));
                    BN_bn2bin(bn, tmp);
                    for (i32 i = 0; i < BN_num_bytes(bn); i++) tmp[i] = ~tmp[i];
                    BN_bin2bn(tmp, BN_num_bytes(bn), bn);
                    free(tmp);

                    BN_add_word(bn, 1);
                }

                char *hex = BN_bn2hex(bn);
                while (strlen(hex) && hex[0] == '0') memmove(hex, hex + 1, strlen(hex));

                // FIXME: Can cause memory leak & some other bad shit if realloc fails
                hash_string = realloc(hash_string, strlen(hash_string) + strlen(hex) + 1);
                strcat(hash_string, hex);
                for (int i = 0; i < strlen(hash_string); i++)
                    hash_string[i] = tolower(hash_string[i]);

                OPENSSL_free(hex);
                BN_free(bn);
                free(hash);
                RSA_free(temp->rsa);

                // Setup Encryption
                EVP_CIPHER_CTX *enc = EVP_CIPHER_CTX_new();
                EVP_EncryptInit(enc, EVP_aes_128_cfb8(), secret, secret);
                EVP_CIPHER_CTX *dec = EVP_CIPHER_CTX_new();
                EVP_EncryptInit(dec, EVP_aes_128_cfb8(), secret, secret);
                client_data->cipher_key = malloc(sizeof(struct encryption_keys));
                ((struct encryption_keys *) client_data->cipher_key)->enc = enc;
                ((struct encryption_keys *) client_data->cipher_key)->dec = dec;
                client_data->params |= CLIENTPARAMS_ENCRYPTED;
                free(secret);

                // Get info on client from Mojang Servers
                CURLU *url = curl_url();
                curl_url_set(url, CURLUPART_SCHEME, "https", 0);
                curl_url_set(url, CURLUPART_HOST, "sessionserver.mojang.com", 0);
                curl_url_set(url, CURLUPART_PATH, "/session/minecraft/hasJoined", 0);

                u8 *temp_string = NULL;
                u8_asprintf(&temp_string, "username=%U&serverId=%s", temp->username, hash_string);
                char *temp_ascii = u8_strconv_to_locale(temp_string);
                curl_url_set(url, CURLUPART_QUERY, temp_ascii, CURLU_APPENDQUERY);
                free(temp_string);
                free(temp_ascii);

                CURL *curl = curl_easy_init();
                curl_easy_setopt(curl, CURLOPT_CURLU, url);
                curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _network_manager_curl_read);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, packet_buffer);

                CURLcode res = curl_easy_perform(curl);
                if (res != CURLE_OK)
                {
                    logger_log_level(
                      LOG_LEVEL_WARN,
                      "Client %d[%U] failed to authenticate",
                      packet->client_id,
                      username);
                    logger_log_level(
                      LOG_LEVEL_DEBUG,
                      "Reason[%d]: curl_easy_perform() failed: %ls",
                      packet->client_id,
                      curl_easy_strerror(res));
                    free(temp->username);
                    free(temp);
                    free(hash_string);

                    // Send disconnect signal
                    buffer_clear(packet_buffer);
                    packet_write_string(
                      packet_buffer,
                      (u8 *) ("{\"text\":\"Failed to Authenticate with Mojang Servers.\"}"));
                    _network_manager_disconnect(
                      clients,
                      packet_buffer,
                      compression_buffer,
                      connected_players,
                      packet->client_id);
                    break;
                }
                buffer_append_u8(packet_buffer, 0);    // Ensure there is a null-terminator

                curl_easy_cleanup(curl);
                curl_url_cleanup(url);
                free(temp);
                free(hash_string);

                // Parse JSON
                json_object *root = json_tokener_parse((const char *) packet_buffer->data);
                if (!root)
                {
                    logger_log_level(
                      LOG_LEVEL_WARN,
                      "Client %d[%U] failed to authenticate",
                      packet->client_id,
                      username);
                    logger_log_level(
                      LOG_LEVEL_DEBUG,
                      "Reason[%d]: Failed to parse JSON",
                      packet->client_id);

                    // Send disconnect signal
                    buffer_clear(packet_buffer);
                    packet_write_string(
                      packet_buffer,
                      (u8 *) ("{\"text\":\"Failed to Authenticate with Mojang Servers.\"}"));
                    _network_manager_disconnect(
                      clients,
                      packet_buffer,
                      compression_buffer,
                      connected_players,
                      packet->client_id);
                    break;
                }

                json_object *id   = json_object_object_get(root, "id");
                json_object *name = json_object_object_get(root, "name");
                if (!id || !name)
                {
                    logger_log_level(
                      LOG_LEVEL_WARN,
                      "Client %d[%U] failed to authenticate",
                      packet->client_id,
                      username);
                    logger_log_level(
                      LOG_LEVEL_DEBUG,
                      "Reason[%d]: Failed to parse JSON",
                      packet->client_id);
                    json_object_put(root);

                    // Send disconnect signal
                    buffer_clear(packet_buffer);
                    packet_write_string(
                      packet_buffer,
                      (u8 *) ("{\"text\":\"Failed to Authenticate with Mojang Servers.\"}"));
                    _network_manager_disconnect(
                      clients,
                      packet_buffer,
                      compression_buffer,
                      connected_players,
                      packet->client_id);
                    break;
                }

                const char *json_username = json_object_get_string(name);
                const char *json_uuid     = json_object_get_string(id);

                // Set Compression Packet
                struct packet *client_packet = malloc(sizeof(struct packet));
                client_packet->client_id     = packet->client_id;
                client_packet->packet_id     = 0x03;
                client_packet->size          = varint_size(COMPRESSION_THRESHOLD);
                client_packet->data          = malloc(client_packet->size);
                varint_encode(client_packet->data, COMPRESSION_THRESHOLD);
                queue_push(clientbound_packets, client_packet);

                // Update Client Parameters
                client_packet            = malloc(sizeof(struct packet));
                client_packet->client_id = packet->client_id;
                client_packet->packet_id = -1;    // Signal Packet
                client_packet->size      = 1;
                client_packet->data      = malloc(client_packet->size);
                client_packet->data[0]   = CLIENTSIGNAL_ENABLE_COMPRESSION;
                queue_push(clientbound_packets, client_packet);

                // Send Login Success
                client_packet            = malloc(sizeof(struct packet));
                client_packet->client_id = packet->client_id;
                client_packet->packet_id = -2;    // Login Success bounce

                // Convert json_uuid back to binary
                bn       = NULL;
                u8 *UUID = malloc(32);
                BN_hex2bn(&bn, json_uuid);
                BN_bn2bin(bn, UUID);
                BN_free(bn);

                buffer_clear(packet_buffer);
                packet_write_uuid(packet_buffer, UUID);
                packet_write_string(packet_buffer, (u8 *) json_username);

                packet_builder_final(packet_buffer, client_packet);
                free(UUID);
                json_object_put(root);

                // Server will bounce this back to client
                queue_push(serverbound_packets, client_packet);

                // Update Client State
                client_packet            = malloc(sizeof(struct packet));
                client_packet->client_id = packet->client_id;
                client_packet->packet_id = -1;    // Signal Packet
                client_packet->size      = 2;
                client_packet->data      = malloc(client_packet->size);
                client_packet->data[0]   = CLIENTSIGNAL_SWITCH_STATE;
                client_packet->data[1]   = CLIENTSTATE_PLAY;
                queue_push(clientbound_packets, client_packet);

                (*connected_players)++;
                logger_log("%U has joined the Server.", username);
                free(username);
            }
            break;
            default:
                logger_log_level(LOG_LEVEL_ERROR, "Unknown Packet! ID: %2X", packet->packet_id);
                pthread_exit(NULL);
            }
        }
        break;
        case CLIENTSTATE_PLAY:
        {
            struct packet *packet_clone = malloc(sizeof(struct packet));
            memcpy(packet_clone, packet, sizeof(struct packet));
            queue_push(serverbound_packets, packet_clone);
        }
        break;
        default:
            logger_log_level(LOG_LEVEL_ERROR, "Unknown Client State! %d", client_data->state);
            pthread_exit(NULL);
        }

        free(packet->data);
        free(packet);
    }
}

void *network_manager_thread(void *args)
{
    struct packet_queue *packet_queues       = args;
    struct queue        *serverbound_packets = &packet_queues->serverbound;
    struct queue        *clientbound_packets = &packet_queues->clientbound;

    struct network_manager *netmgr;
    socket_t               *socket;
    struct slotmap         *clients;
    struct queue           *packet_queue;

    struct buffer *packet_buffer;
    struct buffer *compression_buffer;

    u64 connected_players;

    socket  = malloc(sizeof(socket_t));
    *socket = socket_create();
    if (*socket == SOCKET_ERROR)
    {
        free(socket);
        return NULL;
    }
    if (socket_listen(*socket, PORT) == SOCKET_ERROR)
    {
        socket_destroy(*socket);
        free(socket);
        return NULL;
    }

    clients = malloc(sizeof(struct slotmap));
    slotmap_init(clients, MAX_PLAYERS);

    packet_queue = malloc(sizeof(struct queue));
    queue_init(packet_queue);

    netmgr               = malloc(sizeof(struct network_manager));
    netmgr->socket       = socket;
    netmgr->clients      = clients;
    netmgr->packet_queue = packet_queue;
    pthread_cleanup_push(_network_manager_cleanup, netmgr);

    packet_buffer = malloc(sizeof(struct buffer));
    buffer_init(packet_buffer, 4096);
    compression_buffer = malloc(sizeof(struct buffer));
    buffer_init(compression_buffer, 4096);

    netmgr->packet_buffer      = packet_buffer;
    netmgr->compression_buffer = compression_buffer;

    connected_players         = 0;
    netmgr->connected_players = &connected_players;

    while (true)
    {
        // First, let's accept new connections
        socket_t client;
        while (true)
        {
            // FIXME: Implement something to not just throttle the core that the Network Manager is
            // running on
            client = socket_accept(*socket);
            if (client == SOCKET_ERROR) pthread_exit(NULL);
            if (client == SOCKET_NO_CONN) break;

            struct network_client *client_data = malloc(sizeof(struct network_client));
            client_data->socket                = client;
            client_data->state                 = CLIENTSTATE_HANDSHAKE;
            client_data->params                = 0;
            client_data->cipher_key            = NULL;
            i32 key                            = slotmap_insert(clients, client_data);
            logger_log_level(LOG_LEVEL_DEBUG, "Accepted new client %d", key);
        }

        // Next, let's fetch all the packets from the clients
        for (const struct slotmap_entry *itt = slotmap_end(clients) - 1;
             itt >= slotmap_begin(clients);
             itt--)
        {
            struct network_client *client_data = itt->value;

            i32 ret;
            while (true)
            {
                buffer_clear(packet_buffer);

                // Am able to read 3 bytes because the max-length for any packet is guaranteed to
                // fit in 3 bytes, and the minimum length for a packet is 3 bytes
                if (client_data->params & CLIENTPARAMS_ENCRYPTED)
                {
                    buffer_clear(compression_buffer);
                    ret = buffer_read_socket(compression_buffer, client_data->socket, 3);
                    if (ret == SOCKET_ERROR) pthread_exit(NULL);
                    if (ret == SOCKET_NO_DATA) break;
                    if (ret == SOCKET_NO_CONN)
                    {
                        slotmap_remove(clients, itt->key);
                        _network_manager_destroy_client(client_data);
                        break;
                    }

                    buffer_reserve(packet_buffer, compression_buffer->size);

                    struct encryption_keys *keys = client_data->cipher_key;
                    i32                     len  = packet_buffer->capacity;
                    EVP_DecryptUpdate(
                      keys->dec,
                      packet_buffer->data,
                      &len,
                      compression_buffer->data,
                      compression_buffer->size);
                    packet_buffer->size += compression_buffer->size;
                }
                else
                {
                    ret = buffer_read_socket(packet_buffer, client_data->socket, 3);
                    if (ret == SOCKET_ERROR) pthread_exit(NULL);
                    if (ret == SOCKET_NO_DATA) break;
                    if (ret == SOCKET_NO_CONN)
                    {
                        slotmap_remove(clients, itt->key);
                        _network_manager_destroy_client(client_data);
                        break;
                    }
                }

                i32 index         = 0;
                i32 packet_length = varint_decode(packet_buffer->data);
                index += varint_size(packet_length);

                logger_log_level(
                  LOG_LEVEL_DEBUG,
                  "Got packet of size %d from Client %d",
                  packet_length,
                  itt->key);

                while (packet_length > buffer_size(packet_buffer))
                {
                    if (client_data->params & CLIENTPARAMS_ENCRYPTED)
                    {
                        buffer_clear(compression_buffer);
                        ret = buffer_read_socket(
                          compression_buffer,
                          client_data->socket,
                          packet_length - (buffer_size(packet_buffer) - index));
                        if (ret == SOCKET_ERROR) pthread_exit(NULL);
                        if (ret == SOCKET_NO_DATA) break;

                        buffer_reserve(
                          packet_buffer,
                          packet_buffer->size + compression_buffer->size);

                        struct encryption_keys *keys = client_data->cipher_key;
                        i32                     len = packet_buffer->capacity - packet_buffer->size;
                        EVP_DecryptUpdate(
                          keys->dec,
                          packet_buffer->data + packet_buffer->size,
                          &len,
                          compression_buffer->data,
                          compression_buffer->size);
                        packet_buffer->size += compression_buffer->size;
                    }
                    else
                    {
                        ret = buffer_read_socket(
                          packet_buffer,
                          client_data->socket,
                          packet_length - (buffer_size(packet_buffer) - index));
                        if (ret == SOCKET_ERROR) pthread_exit(NULL);
                        if (ret == SOCKET_NO_DATA) break;
                    }
                }

                struct packet *packet = malloc(sizeof(struct packet));
                packet->client_id     = itt->key;

                if (client_data->params & CLIENTPARAMS_COMPRESSED)
                {
                    i32 data_length = varint_decode(packet_buffer->data + index);
                    index += varint_size(data_length);
                    if (data_length == 0)
                    {
                        // Uncompressed packet
                        packet->packet_id = packet_buffer->data[index++];
                        packet->size      = packet_length - varint_size(data_length) - 1;
                        if (packet->size > 0)
                        {
                            packet->data = malloc(packet->size);
                            memcpy(packet->data, packet_buffer->data + index, packet->size);
                        }
                        else
                            packet->data = NULL;
                    }
                    else
                    {
                        // Compressed packet
                        buffer_clear(compression_buffer);
                        buffer_reserve(compression_buffer, data_length);
                        size_t uncompressed_size = compression_buffer->capacity;
                        ret                      = zng_uncompress(
                          compression_buffer->data,
                          &uncompressed_size,
                          packet_buffer->data + index,
                          packet_length - varint_size(data_length) - 1);
                        if (ret != Z_OK)
                        {
                            logger_log_level(
                              LOG_LEVEL_DEBUG,
                              "Client %d failed to decompress packet. Error %d",
                              packet->client_id,
                              ret);

                            buffer_clear(packet_buffer);
                            packet_write_string(
                              packet_buffer,
                              (u8 *) ("{\"text\":\"Decompression failed.\"}"));
                            _network_manager_disconnect(
                              clients,
                              packet_buffer,
                              compression_buffer,
                              &connected_players,
                              packet->client_id);

                            break;
                        }

                        packet->packet_id = compression_buffer->data[0];
                        packet->size      = uncompressed_size - 1;
                        packet->data      = malloc(packet->size);
                        memcpy(packet->data, compression_buffer->data + 1, packet->size);
                    }
                }
                else
                {
                    // Since there aren't more than 127 packets, we can just read a byte
                    packet->packet_id = packet_buffer->data[index++];

                    packet->size = packet_length - 1;
                    if (packet->size > 0)
                    {
                        packet->data = malloc(sizeof(u8) * packet->size);
                        memcpy(packet->data, packet_buffer->data + index, packet->size);
                    }
                    else
                        packet->data = NULL;
                }

                queue_push(packet_queue, packet);
            }
        }

        // Next, let's handle the packets
        _network_manager_process_packets(
          clients,
          packet_queue,
          packet_queues,
          packet_buffer,
          compression_buffer,
          &connected_players);

        // And finally, let's send the packets to the clients
        // TODO: Bulk send the packets for each client
        struct packet *packet;
        while ((packet = queue_pop(clientbound_packets)))
        {
            struct network_client *client_data = slotmap_get(clients, packet->client_id);
            if (client_data == NULL) continue;

            socket_t client_socket = client_data->socket;
            if (client_socket == SOCKET_ERROR)
            {
                logger_log_level(
                  LOG_LEVEL_DEBUG,
                  "Client %d is no longer connected!",
                  packet->client_id);
                slotmap_remove(clients, packet->client_id);
                _network_manager_destroy_client(client_data);
                continue;
            }

            buffer_clear(packet_buffer);
            if (packet->packet_id == -1)    // Signal
            {
                switch (packet->data[0])
                {
                case CLIENTSIGNAL_DISCONNECT:
                    buffer_append(packet_buffer, packet->data, packet->size);
                    _network_manager_disconnect(
                      clients,
                      packet_buffer,
                      compression_buffer,
                      &connected_players,
                      packet->client_id);
                    break;
                case CLIENTSIGNAL_ENABLE_COMPRESSION:
                    client_data->params |= CLIENTPARAMS_COMPRESSED;
                    break;
                case CLIENTSIGNAL_SWITCH_STATE: client_data->state = packet->data[1]; break;
                default:
                    logger_log_level(
                      LOG_LEVEL_WARN,
                      "Unknown signal %d on Client %d",
                      packet->data[0],
                      packet->client_id);
                }
                free(packet->data);
                free(packet);
                continue;
            }

            i32 index = 0;
            if (client_data->params & CLIENTPARAMS_COMPRESSED)
            {
                if (_network_manager_compress_packet(packet_buffer, compression_buffer, packet) < 0)
                {
                    buffer_clear(packet_buffer);
                    packet_write_string(
                      packet_buffer,
                      (u8 *) ("{\"text\":\"Compression failed.\""));
                    _network_manager_disconnect(
                      clients,
                      packet_buffer,
                      compression_buffer,
                      &connected_players,
                      packet->client_id);

                    free(packet->data);
                    free(packet);
                    continue;
                }
            }
            else
            {
                varint_encode(packet_buffer->data, packet->size + 1);    // Packet Length
                index += varint_size(packet->size + 1);
                buffer_reserve(packet_buffer, index + 1 + packet->size);
                packet_buffer->data[index++] = packet->packet_id;    // Packet ID
                memcpy(packet_buffer->data + index, packet->data,
                       packet->size);    // Packet Data
                packet_buffer->size = index + packet->size;
            }

            if (client_data->params & CLIENTPARAMS_ENCRYPTED)
            {
                struct encryption_keys *ctx = client_data->cipher_key;

                buffer_reserve(compression_buffer, packet_buffer->size);
                i32 len = compression_buffer->capacity;
                EVP_EncryptUpdate(
                  ctx->enc,
                  compression_buffer->data,
                  &len,
                  packet_buffer->data,
                  packet_buffer->size);

                // FIXME: Replace with actual handling of failure
                i32 ret = socket_send(client_socket, compression_buffer->data, len);
                if (ret == SOCKET_ERROR) pthread_exit(NULL);
            }
            else
            {
                // FIXME: Replace with actual handling of failure
                i32 ret = socket_send(client_socket, packet_buffer->data, packet_buffer->size);
                if (ret == SOCKET_ERROR) pthread_exit(NULL);
            }

            free(packet->data);
            free(packet);
        }
    }

    pthread_cleanup_pop(1);
}