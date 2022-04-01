#include "server.h"

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <curl/curl.h>
#include <openssl/crypto.h>

#include "logger/logger.h"
#include "network/network_manager.h"

#define TPS 20

bool running;
int  sigint_count;

void server_stop(int sig)
{
    running = false;
    sigint_count++;
    if (sigint_count > 1)
    {
        printf(
          "\x1b[0;31m[ERROR] Received Multiple SIGINT, assuming Server is stuck. Forcing "
          "shutdown.\x1b[0m\n");
        exit(sig);
    }
}

void server_run()
{
    sigint_count = 0;
    running      = true;    // So the it doesn't ignore the SIGINT
    signal(SIGINT, server_stop);

    pthread_t network_thread;
    // pthread_t *world_threads;
    // pthread_t plugin_thread;

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

    logger_log("Starting Server!\n");
    while (running)
    {
        struct packet *packet;
        while ((packet = queue_pop(serverbound_packets)))
        {
            logger_log_level(
              LOG_LEVEL_DEBUG,
              "Packet received from client %d\n",
              packet->client_id);
            logger_log_level(LOG_LEVEL_DEBUG, "Packet ID: %02hhx\n", packet->packet_id);
            logger_log_level(LOG_LEVEL_DEBUG, "Packet size: %d\n", packet->size);

            if (packet->packet_id < 0)
            {
                switch (packet->packet_id)
                {
                case -2:
                {
                    logger_log_level(
                      LOG_LEVEL_DEBUG,
                      "Login Success packet with id %02hhx received\n",
                      packet->data[0]);

                    struct packet *bounce_packet = malloc(sizeof(struct packet));
                    bounce_packet->client_id     = packet->client_id;
                    bounce_packet->packet_id     = 0x02;
                    bounce_packet->size          = packet->size;
                    bounce_packet->data          = malloc(bounce_packet->size);
                    memcpy(bounce_packet->data, packet->data, packet->size);

                    queue_push(clientbound_packets, bounce_packet);
                }
                break;
                default: break;
                }

                free(packet->data);
                free(packet);
                continue;
            }

            free(packet->data);
            free(packet);
        }

        // Tick code
        usleep(1000 / TPS);
    }

    logger_log("Stopping Server\n");

    pthread_cancel(network_thread);
    pthread_join(network_thread, NULL);

    struct packet *packet;
    while ((packet = queue_pop(&packet_queue.clientbound))) free(packet);
    while ((packet = queue_pop(&packet_queue.serverbound))) free(packet);
    queue_destroy(&packet_queue.clientbound);
    queue_destroy(&packet_queue.serverbound);
}