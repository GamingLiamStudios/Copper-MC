#include "socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#if !defined(PLATFORM_WINDOWS) && !defined(PLATFORM_UNIX)
#error Platform not supported.
#endif

inline socket_t socket_create()
{
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket_create: socket() failed\n");
        return SOCKET_ERROR;
    }

    return sock;
}
inline void socket_destroy(socket_t socket)
{
#ifdef PLATFORM_UNIX
    close(socket);
#endif
}

i32 socket_connect(socket_t *socket, const char *host, i32 port)
{
    // TODO: Implement socket_connect
    return -1;
}

i32 socket_listen(socket_t socket, i32 port)
{
    // Set non-blocking
    const int old_flags = fcntl(socket, F_GETFL, 0);
    if (old_flags == -1)
    {
        perror("socket_listen: fcntl() failed");
        return SOCKET_ERROR;
    }
    const int new_flags = fcntl(socket, F_SETFL, old_flags | O_NONBLOCK);
    if (new_flags == -1)
    {
        perror("socket_listen: fcntl() failed");
        return SOCKET_ERROR;
    }

    // Bind port to socket
    struct sockaddr_in serv_addr = { 0 };

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(port);
#if defined(PLATFORM_UNIX)
    serv_addr.sin_addr.s_addr = INADDR_ANY;
#endif

    if (bind(socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("socket_listen: bind() failed.\n");
        return SOCKET_ERROR;
    }

    // Start listening for new connections
    if (listen(socket, SOMAXCONN) < 0)
    {
        printf("socket_listen: listen() failed.\n");
        return SOCKET_ERROR;
    }

    return 1;
}

socket_t socket_accept(socket_t socket)
{
    socket_t client = accept(socket, NULL, NULL);
    if (client < 0)
    {
        if (errno == EWOULDBLOCK)
            return SOCKET_NO_CONN;
        else
        {
            perror("socket_accept: accept() failed");
            return SOCKET_ERROR;
        }
    }

    return client;
}
i32 socket_recv(socket_t socket, void *buffer, i32 buffer_size)
{
    i32 bytes = recv(socket, buffer, buffer_size, 0);
    if (bytes < 0)
    {
        if (errno == EWOULDBLOCK)
            return SOCKET_NO_DATA;
        else
        {
            perror("socket_recv: recv() failed");
            return SOCKET_ERROR;
        }
    }
    else if (bytes == 0)
    {
        printf("socket_recv: Connection closed.\n");
        return SOCKET_NO_CONN;
    }

    return bytes;
}
