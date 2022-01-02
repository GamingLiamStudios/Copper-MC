#include "server.h"

#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include "network/network_manager.h"

#define TPS 20

// TODO: Make this not be a global variable
pthread_t network_thread;
// pthread_t *world_threads;
// pthread_t plugin_thread;

void server_stop(int sig)
{
    printf("Stopping Server\n");

    pthread_cancel(network_thread);
    pthread_join(network_thread, NULL);

    // TODO: Clean stop of server
    exit(0);
}

void server_run()
{
    signal(SIGINT, server_stop);

    struct packet_queue packet_queue;
    struct queue       *serverbound_packets;
    struct queue       *clientbound_packets;

    // Initialize the packet queue
    queue_init(&packet_queue.serverbound);
    queue_init(&packet_queue.clientbound);
    serverbound_packets = &packet_queue.serverbound;
    clientbound_packets = &packet_queue.clientbound;

    // Initialize the network manager
    pthread_create(&network_thread, NULL, network_manager_thread, &packet_queue);

    while (true)
    {
        // Little test code
        struct packet *packet;
        while (true)
        {
            packet = queue_pop(serverbound_packets);
            if (packet == NULL) break;

            printf("Packet received from client %d\n", packet->client_id);
            printf("Packet ID: %d\n", packet->packet_id);
            printf("Packet size: %d\n", packet->size);

            free(packet->data);
            free(packet);
        }

        // Tick code
        usleep(1000 / TPS);
    }
}