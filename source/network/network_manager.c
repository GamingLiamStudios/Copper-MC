#include "network_manager.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "server/server.h"
#include "util/containers/slotmap.h"
#include "util/containers/buffer.h"

#include "varints.h"

#define MAX_PLAYERS 20
#define PORT        25565

struct network_manager
{
    socket_t       *socket;
    struct slotmap *clients;
};

struct network_client
{
    socket_t socket;
    enum
    {
        CLIENTSTATE_HANDSHAKE,
        CLIENTSTATE_LOGIN,
        CLIENTSTATE_PLAY
    } state;
    enum
    {
        CLIENTPARAMS_COMPRESSED = 0b01,
        CLIENTPARAMS_ENCRYPTED  = 0b10
    } params;
};

void network_manager_cleanup(void *args)
{
    struct network_manager *manager = args;

    // TODO: Send disconnect signal
    for (const struct slotmap_entry *itt = slotmap_end(manager->clients) - 1;
         itt >= slotmap_begin(manager->clients);
         itt--)
        socket_destroy(((struct network_client *) itt->value)->socket);

    slotmap_destroy(manager->clients);
    socket_destroy(*manager->socket);

    free(manager->clients);
    free(manager->socket);
    free(manager);

    printf("Closing Network Manager\n");
}

void *network_manager_thread(void *args)
{
    struct packet_queue *packet_queue        = args;
    struct queue        *serverbound_packets = &packet_queue->serverbound;
    struct queue        *clientbound_packets = &packet_queue->clientbound;

    struct network_manager *netmgr;
    struct slotmap         *clients;
    socket_t                socket;

    socket = socket_create();
    if (socket == SOCKET_ERROR) return NULL;
    if (socket_listen(socket, PORT) == SOCKET_ERROR)
    {
        socket_destroy(socket);
        return NULL;
    }

    clients = (struct slotmap *) malloc(sizeof(struct slotmap));
    slotmap_init(clients, MAX_PLAYERS);

    netmgr          = (struct network_manager *) malloc(sizeof(struct network_manager));
    netmgr->socket  = (socket_t *) malloc(sizeof(socket_t));
    *netmgr->socket = socket;
    netmgr->clients = clients;
    pthread_cleanup_push(network_manager_cleanup, netmgr);

    struct buffer incoming_buffer;
    buffer_init(&incoming_buffer, 4096);

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
                buffer_clear(&incoming_buffer);

                ret = buffer_read_socket(&incoming_buffer, client_data->socket, 5);
                if (ret == SOCKET_ERROR) pthread_exit(NULL);
                if (ret == SOCKET_NO_DATA) break;
                if (ret == SOCKET_NO_CONN)
                {
                    socket_destroy(client_data->socket);
                    slotmap_remove(clients, itt->key);
                    free(client_data);
                    pthread_exit(NULL);
                }

                i32 index         = 0;
                i32 packet_length = varint_decode(incoming_buffer.data);
                index += varint_size(packet_length);

                printf("Got packet of size %d\n", packet_length);

                if (packet_length > buffer_size(&incoming_buffer))
                {
                    ret = buffer_read_socket(
                      &incoming_buffer,
                      client_data->socket,
                      packet_length - (buffer_size(&incoming_buffer) - index));
                    if (ret == SOCKET_ERROR) pthread_exit(NULL);
                    if (ret == SOCKET_NO_DATA) break;
                }

                struct packet *packet = (struct packet *) malloc(sizeof(struct packet));
                packet->client_id     = itt->key;

                // Since there aren't more than 127 packets, we can just read a byte
                packet->packet_id = incoming_buffer.data[index++];

                packet->size = packet_length - 1;
                if (packet->size > 0)
                {
                    packet->data = (u8 *) malloc(sizeof(u8) * packet->size);
                    memcpy(packet->data, incoming_buffer.data + index, packet->size);
                }

                queue_push(serverbound_packets, packet);
            }
        }
    }

    pthread_cleanup_pop(1);
}