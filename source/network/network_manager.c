#include "network_manager.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "server/server.h"
#include "util/containers/slotmap.h"
#include "util/containers/buffer.h"
#include "util/containers/queue.h"

#include "varints.h"

#define MAX_PLAYERS 20
#define PORT        25565

struct network_manager
{
    socket_t       *socket;
    struct slotmap *clients;
    struct queue   *packet_queue;
    struct buffer  *packet_buffer;
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

void _network_manager_cleanup(void *args)
{
    struct network_manager *manager = args;

    // TODO: Send disconnect signal
    for (const struct slotmap_entry *itt = slotmap_end(manager->clients) - 1;
         itt >= slotmap_begin(manager->clients);
         itt--)
    {
        socket_destroy(((struct network_client *) itt->value)->socket);
        free(itt->value);
        slotmap_remove(manager->clients, itt->key);
    }

    slotmap_destroy(manager->clients);
    socket_destroy(*manager->socket);

    struct packet *packet;
    while ((packet = queue_pop(manager->packet_queue))) free(packet);
    queue_destroy(manager->packet_queue);

    buffer_destroy(manager->packet_buffer);

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
                printf(
                  "Sent status packet of length %d to client %d\n",
                  status_packet->size,
                  packet->client_id);
            }
            break;
            case 0x01:
                // Status Ping
                queue_push(clientbound_packets, packet);
                break;
            default: printf("Unknown Packet! ID: %2X\n", packet->packet_id); pthread_exit(NULL);
            }
            break;
        }
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
    socket_t                socket;
    struct slotmap         *clients;
    struct queue           *packet_queue;
    struct buffer          *packet_buffer;

    socket = socket_create();
    if (socket == SOCKET_ERROR) return NULL;
    if (socket_listen(socket, PORT) == SOCKET_ERROR)
    {
        socket_destroy(socket);
        return NULL;
    }

    clients = (struct slotmap *) malloc(sizeof(struct slotmap));
    slotmap_init(clients, MAX_PLAYERS);

    packet_queue = (struct queue *) malloc(sizeof(struct queue));
    queue_init(packet_queue);

    netmgr               = (struct network_manager *) malloc(sizeof(struct network_manager));
    netmgr->socket       = (socket_t *) malloc(sizeof(socket_t));
    *netmgr->socket      = socket;
    netmgr->clients      = clients;
    netmgr->packet_queue = packet_queue;
    pthread_cleanup_push(_network_manager_cleanup, netmgr);

    packet_buffer = (struct buffer *) malloc(sizeof(struct buffer));
    buffer_init(packet_buffer, 4096);
    netmgr->packet_buffer = packet_buffer;

    while (true)
    {
        // First, let's accept new connections
        socket_t client;
        while (true)
        {
            client = socket_accept(socket);
            if (client == SOCKET_ERROR) pthread_exit(NULL);
            if (client == SOCKET_NO_CONN) break;

            printf("Accepted new client!\n");
            struct network_client *client_data =
              (struct network_client *) malloc(sizeof(struct network_client));
            client_data->socket = client;
            client_data->state  = CLIENTSTATE_HANDSHAKE;
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

            if (client_data->params & CLIENTPARAMS_COMPRESSED)
            {
                printf("Compressed packets? These aren't supported!\n");
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

                struct packet *packet = (struct packet *) malloc(sizeof(struct packet));
                packet->client_id     = itt->key;

                // Since there aren't more than 127 packets, we can just read a byte
                packet->packet_id = packet_buffer->data[index++];

                packet->size = packet_length - 1;
                if (packet->size > 0)
                {
                    packet->data = (u8 *) malloc(sizeof(u8) * packet->size);
                    memcpy(packet->data, packet_buffer->data + index, packet->size);
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
            printf("Sending packet to client %d\n", packet->client_id);
            struct network_client *client = slotmap_get(clients, packet->client_id);

            socket_t client_socket = client->socket;
            if (client_socket == SOCKET_ERROR)
            {
                printf("Client %d is no longer connected!\n", packet->client_id);
                free(packet->data);
                free(packet);
                continue;
            }

            i32 index = 0;
            buffer_clear(packet_buffer);
            varint_encode(packet_buffer->data, packet->size + 1);    // Packet Length
            index += varint_size(packet->size + 1);
            buffer_reserve(packet_buffer, index + 1 + packet->size);
            packet_buffer->data[index++] = packet->packet_id;                   // Packet ID
            memcpy(packet_buffer->data + index, packet->data, packet->size);    // Packet Data

            i32 ret = socket_send(client_socket, packet_buffer->data, index + packet->size);
            if (ret == SOCKET_ERROR) pthread_exit(NULL);

            free(packet->data);
            free(packet);
        }
    }

    pthread_cleanup_pop(1);
}