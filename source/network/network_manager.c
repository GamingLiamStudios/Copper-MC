#include "network_manager.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <zlib-ng.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>

#include "server/server.h"
#include "util/containers/slotmap.h"
#include "util/containers/buffer.h"
#include "util/containers/queue.h"

#include "varints.h"

#define MAX_PLAYERS 20
#define PORT        25565

#define COMPRESSION_THRESHOLD 256

struct network_manager
{
    socket_t       *socket;
    struct slotmap *clients;
    struct queue   *packet_queue;

    struct buffer *packet_buffer;
    struct buffer *compression_buffer;
};

struct network_client
{
    socket_t socket;
    enum
    {
        CLIENTSTATE_HANDSHAKE,
        CLIENTSTATE_STATUS,
        CLIENTSTATE_LOGIN,
        CLIENTSTATE_PLAY
    } state;
    enum
    {
        CLIENTPARAMS_COMPRESSED = 0b01,
        CLIENTPARAMS_ENCRYPTED  = 0b10
    } params;
};

// These are 'signals'. They are used to modify the state of the client.
enum
{
    CLIENTSIGNAL_DISCONNECT,
    CLIENTSIGNAL_ENABLE_COMPRESSION,
    CLIENTSIGNAL_ENABLE_ENCRYPTION,
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
            printf("Error %d: Failed to compress packet!\n", ret);
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
    varint_encode(
      packet_buffer->data,
      varint_size(data_length) + compression_buffer->size);    // Packet Length
    index += varint_size(varint_size(data_length) + data_length);
    buffer_reserve(packet_buffer, index + varint_size(data_length) + data_length);
    varint_encode(packet_buffer->data + index, data_length);    // Data Length
    index += varint_size(data_length);
    memcpy(    // Compressed Data(Packet ID + Data)
      packet_buffer->data + index,
      compression_buffer->data,
      compression_buffer->size);
    packet_buffer->size = index + compression_buffer->size;

    return 0;
}

void _network_manager_disconnect(
  struct slotmap *clients,
  struct buffer  *packet_buffer,
  struct buffer  *compression_buffer,
  i32             client_id)
{
    struct network_client *client = slotmap_get(clients, client_id);

    struct packet packet;
    packet.packet_id = -1;
    switch (client->state)
    {
    case CLIENTSTATE_PLAY: packet.packet_id = 0x40;
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

            i32 index              = 0;
            i32 packet_buffer_size = 1 + string_length + varint_size(string_length);
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
                varint_encode(packet_buffer->data, packet.size + 1);    // Packet Length
                index += varint_size(packet.size + 1);
                buffer_reserve(packet_buffer, index + 1 + packet.size);
                packet_buffer->data[index++] = packet.packet_id;    // Packet ID
                memcpy(packet_buffer->data + index, packet.data,
                       packet.size);    // Packet Data
                packet_buffer->size = index + packet.size;
            }

            i32 ret = socket_send(client->socket, packet_buffer->data, packet_buffer->size);
            if (ret == SOCKET_ERROR) pthread_exit(NULL);    // ...what

            printf("Client %d disconnected!\n", client_id);
        }
        break;
    default: break;
    }

    socket_destroy(client->socket);
    free(slotmap_get(clients, client_id));
    slotmap_remove(clients, client_id);
}

void _network_manager_cleanup(void *args)
{
    struct network_manager *manager = args;

    const char *disconnect_message = "{\"text\":\"Server shutting down\"}";
    buffer_clear(manager->packet_buffer);
    buffer_append_u8(manager->packet_buffer, strlen(disconnect_message));
    buffer_append(manager->packet_buffer, disconnect_message, strlen(disconnect_message));
    for (const struct slotmap_entry *itt = slotmap_end(manager->clients) - 1;
         itt >= slotmap_begin(manager->clients);
         itt--)
        _network_manager_disconnect(
          manager->clients,
          manager->packet_buffer,
          manager->compression_buffer,
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
    free(manager);

    printf("Closing Network Manager\n");
}

void _network_manager_process_packets(
  struct slotmap      *clients,
  struct queue        *packet_queue,
  struct packet_queue *packet_queues)
{
    struct queue *serverbound_packets = &packet_queues->serverbound;
    struct queue *clientbound_packets = &packet_queues->clientbound;

    struct packet *packet;
    while ((packet = queue_pop(packet_queue)))
    {
        struct network_client *client_data = slotmap_get(clients, packet->client_id);

        switch (client_data->state)
        {
        case CLIENTSTATE_HANDSHAKE:
        {
            if (packet->packet_id > 0x00)
            {
                printf("Unknown Packet! ID: %2X\n", packet->packet_id);
                pthread_exit(NULL);
            }

            // Handshake
            i32 index            = 0;
            i32 protocol_version = varint_decode(packet->data + index);
            index += varint_size(protocol_version);
            i32 hostname_length = varint_decode(packet->data + index);
            index += varint_size(protocol_version);
            index += hostname_length;    // Since we have no need for hostname
            index += 2;                  // Or the port.

            i32 next_state = varint_decode(packet->data + index);
            index += varint_size(protocol_version);

            client_data->state = next_state;
            printf("Handshaken with client %d into state %d\n", packet->client_id, next_state);
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

                const char *status_format =
                  "{\"version\":{\"name\":\"1.8.9\",\"protocol\":47},\"players\":{\"max\":%d,"
                  "\"online\":%d,\"sample\":[]},\"description\":{\"text\":\"GLS' Copper-MC Testing "
                  "Server\"}}";
                i32 string_length =
                  snprintf(NULL, 0, status_format, MAX_PLAYERS, slotmap_size(clients));

                status_packet->size = varint_size(string_length) + string_length;
                status_packet->data = malloc(status_packet->size + 1);    // For Null-Terminator

                varint_encode(status_packet->data, string_length);
                snprintf(
                  (char *) status_packet->data + varint_size(string_length),
                  string_length + 1,
                  status_format,
                  MAX_PLAYERS,
                  slotmap_size(clients));

                queue_push(clientbound_packets, status_packet);
            }
            break;
            case 0x01:
            {
                // Status Ping
                queue_push(clientbound_packets, packet);

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
            default: printf("Unknown Packet! ID: %2X\n", packet->packet_id); pthread_exit(NULL);
            }
            break;
        }
        case CLIENTSTATE_LOGIN:
        {
            switch (packet->packet_id)
            {
            case 0x00:
            {
                // Login Start
                i32   username_length = varint_decode(packet->data);
                char *username        = malloc(username_length + 1);
                memcpy(username, packet->data + varint_size(username_length), username_length);
                username[username_length] = '\0';

                printf("Client %d logged in as %s\n", packet->client_id, username);

                // Check if Local host
                struct sockaddr_in rem_addr, loc_addr;
                u32                len = sizeof(rem_addr);

                getpeername(client_data->socket, (struct sockaddr *) &rem_addr, &len);
                getsockname(client_data->socket, (struct sockaddr *) &loc_addr, &len);
                if (rem_addr.sin_addr.s_addr == loc_addr.sin_addr.s_addr)
                {
                    // Local host
                    printf("Client %d is localhost\n", packet->client_id);

                    // Generate Player UUID
                    const char *UUID_hash_format = "OfflinePlayer:";
                    u8 *UUID_hash_string = malloc(strlen(UUID_hash_format) + strlen(username));
                    memcpy(UUID_hash_string, UUID_hash_format, strlen(UUID_hash_format));
                    memcpy(UUID_hash_string + strlen(UUID_hash_format), username, strlen(username));

                    char *UUID = malloc(MD5_DIGEST_LENGTH);
                    MD5(UUID_hash_string, strlen(UUID_hash_format) + strlen(username), (u8 *) UUID);
                    UUID[6] = (UUID[6] & 0x0f) | 0x30;

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
                    client_packet->packet_id = 0x02;
                    client_packet->size =
                      varint_size(strlen(username)) + strlen(username) + varint_size(36) + 36;
                    client_packet->data = malloc(client_packet->size);

                    varint_encode(client_packet->data, 36);
                    char *fUUID_string = malloc(37);
                    snprintf(
                      fUUID_string,
                      37,
                      "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx"
                      "%02hhx%02hhx%02hhx%02hhx%02hhx",
                      UUID[0],
                      UUID[1],
                      UUID[2],
                      UUID[3],
                      UUID[4],
                      UUID[5],
                      UUID[6],
                      UUID[7],
                      UUID[8],
                      UUID[9],
                      UUID[10],
                      UUID[11],
                      UUID[12],
                      UUID[13],
                      UUID[14],
                      UUID[15]);
                    memcpy(client_packet->data + 1, fUUID_string, 36);
                    memcpy(
                      client_packet->data + 37,
                      packet->data,
                      packet->size);    // Save some work by reusing the Login Start packet
                    free(fUUID_string);

                    queue_push(clientbound_packets, client_packet);

                    // Update Client State
                    client_packet            = malloc(sizeof(struct packet));
                    client_packet->client_id = packet->client_id;
                    client_packet->packet_id = -1;    // Signal Packet
                    client_packet->size      = 2;
                    client_packet->data      = malloc(client_packet->size);
                    client_packet->data[0]   = CLIENTSIGNAL_SWITCH_STATE;
                    client_packet->data[1]   = CLIENTSTATE_PLAY;
                    queue_push(clientbound_packets, client_packet);
                }
                else
                {
                    // Remote host
                    printf("Client %d is remotehost\n", packet->client_id);
                }
            }
            break;
            case 0x01:
            default: printf("Unknown Packet! ID: %2X\n", packet->packet_id); pthread_exit(NULL);
            }
        }
        break;
        default: printf("Unknown Client State! %d\n", client_data->state); pthread_exit(NULL);
        }
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

    socket  = malloc(sizeof(socket_t));
    *socket = socket_create();
    if (*socket == SOCKET_ERROR) return NULL;
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

    while (true)
    {
        // FIXME: Figure out what's causing the invalid sockets after the first connection
        // First, let's accept new connections
        socket_t client;
        while (true)
        {
            client = socket_accept(*socket);
            if (client == SOCKET_ERROR) pthread_exit(NULL);
            if (client == SOCKET_NO_CONN) break;

            printf("Accepted new client!\n");
            struct network_client *client_data = malloc(sizeof(struct network_client));
            client_data->socket                = client;
            client_data->state                 = CLIENTSTATE_HANDSHAKE;
            client_data->params                = 0;
            slotmap_insert(clients, client_data);
        }

        // Next, let's fetch all the packets from the clients
        for (const struct slotmap_entry *itt = slotmap_end(clients) - 1;
             itt >= slotmap_begin(clients);
             itt--)
        {
            struct network_client *client_data = itt->value;

            if (client_data->params & CLIENTPARAMS_ENCRYPTED)
            {
                printf("Encrypted packets? These aren't supported!\n");
                pthread_exit(NULL);
            }

            i32 ret;
            while (true)
            {
                buffer_clear(packet_buffer);

                ret = buffer_read_socket(packet_buffer, client_data->socket, 5);
                if (ret == SOCKET_ERROR) pthread_exit(NULL);
                if (ret == SOCKET_NO_DATA) break;
                if (ret == SOCKET_NO_CONN)
                {
                    socket_destroy(client_data->socket);
                    slotmap_remove(clients, itt->key);
                    free(client_data);
                    break;
                }

                i32 index         = 0;
                i32 packet_length = varint_decode(packet_buffer->data);
                index += varint_size(packet_length);

                printf(
                  "Got packet of size %d from Client %d\n",
                  packet_length,
                  client_data->socket);

                if (packet_length > buffer_size(packet_buffer))
                {
                    ret = buffer_read_socket(
                      packet_buffer,
                      client_data->socket,
                      packet_length - (buffer_size(packet_buffer) - index));
                    if (ret == SOCKET_ERROR) pthread_exit(NULL);
                    if (ret == SOCKET_NO_DATA) break;
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
                        i32    ret               = zng_uncompress(
                          compression_buffer->data,
                          &uncompressed_size,
                          packet_buffer->data + index,
                          packet_length - varint_size(data_length) - 1);
                        if (ret != Z_OK)
                        {
                            printf(
                              "Error %d: Failed to uncompress packet! Disconnect client %d\n",
                              ret,
                              packet->client_id);

                            buffer_clear(packet_buffer);
                            buffer_append(packet_buffer, "Decompression failed.", 19);
                            _network_manager_disconnect(
                              clients,
                              packet_buffer,
                              compression_buffer,
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
        _network_manager_process_packets(clients, packet_queue, packet_queues);

        // And finally, let's send the packets to the clients
        // TODO: Bulk send the packets for each client
        struct packet *packet;
        while ((packet = queue_pop(clientbound_packets)))
        {
            struct network_client *client = slotmap_get(clients, packet->client_id);
            if (client == NULL) continue;

            socket_t client_socket = client->socket;
            if (client_socket == SOCKET_ERROR)
            {
                printf("Client %d is no longer connected!\n", packet->client_id);
                socket_destroy(client_socket);
                free(slotmap_get(clients, packet->client_id));
                slotmap_remove(clients, packet->client_id);
                free(packet->data);
                free(packet);
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
                      packet->client_id);
                    break;
                case CLIENTSIGNAL_ENABLE_COMPRESSION:
                    client->params |= CLIENTPARAMS_COMPRESSED;
                    break;
                case CLIENTSIGNAL_ENABLE_ENCRYPTION:
                    client->params |= CLIENTPARAMS_ENCRYPTED;
                    break;
                case CLIENTSIGNAL_SWITCH_STATE: client->state = packet->data[1]; break;
                default: printf("Client %d sent an unknown signal!\n", packet->client_id);
                }
                free(packet->data);
                free(packet);
                continue;
            }

            i32 index = 0;
            if (client->params & CLIENTPARAMS_COMPRESSED)
            {
                if (_network_manager_compress_packet(packet_buffer, compression_buffer, packet) < 0)
                {
                    buffer_clear(packet_buffer);
                    buffer_append(packet_buffer, "Compression failed.", 19);
                    _network_manager_disconnect(
                      clients,
                      packet_buffer,
                      compression_buffer,
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

            if (client->params & CLIENTPARAMS_ENCRYPTED)
            {
                printf("Encrypted packets? These aren't supported!\n");
                pthread_exit(NULL);
            }

            i32 ret = socket_send(client_socket, packet_buffer->data, packet_buffer->size);
            if (ret == SOCKET_ERROR) pthread_exit(NULL);

            free(packet->data);
            free(packet);
        }
    }

    pthread_cleanup_pop(1);
}