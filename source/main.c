#include <stdio.h>
#include "util/types.h"

#include "network/socket.h"
#include "util/containers/queue.h"

int main(int argv, char **argc)
{
    printf("Starting Server!\n");

    socket_t socket = socket_create();
    if (socket == SOCKET_ERROR) return -1;

    i32 ret = socket_listen(socket, 25565);
    if (ret == SOCKET_ERROR) return -1;

    while (1)
    {
        socket_t client = socket_accept(socket);
        if (client == SOCKET_ERROR) return -1;

        char buffer[1024];
        i32  bytes = socket_recv(client, buffer, 1024);
        if (bytes == SOCKET_ERROR) return -1;

        printf("Received %d bytes: %s\n", bytes, buffer);
        socket_destroy(client);
    }
    return 0;
}