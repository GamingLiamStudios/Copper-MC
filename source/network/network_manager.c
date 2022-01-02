#include "network_manager.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "util/containers/slotmap.h"

#define MAX_PLAYERS 20
#define PORT        25565

struct network_manager
{
    socket_t       *socket;
    struct slotmap *clients;
};

void network_manager_cleanup(void *args)
{
    struct network_manager *manager = args;
    slotmap_destroy(manager->clients);
    socket_destroy(*manager->socket);

    free(manager->clients);
    free(manager->socket);
    free(manager);
}

void network_manager_thread()
{
    struct network_manager *netmgr;
    struct slotmap         *clients;
    socket_t                socket;

    socket = socket_create();
    if (socket == SOCKET_ERROR) return;
    if (socket_listen(socket, PORT) == SOCKET_ERROR)
    {
        socket_destroy(socket);
        return;
    }

    clients = (struct slotmap *) malloc(sizeof(struct slotmap));
    slotmap_init(clients, MAX_PLAYERS);

    netmgr          = (struct network_manager *) malloc(sizeof(struct network_manager));
    netmgr->socket  = (socket_t *) malloc(sizeof(socket_t));
    *netmgr->socket = socket;
    netmgr->clients = clients;
    pthread_cleanup_push(network_manager_cleanup, netmgr);

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
            socket_destroy(client);
        }
    }

    pthread_cleanup_pop(1);
}