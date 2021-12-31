#include "socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <unistd.h>

#if !defined(PLATFORM_WINDOWS) && !defined(PLATFORM_UNIX)
#error Platform not supported.
#endif

inline socket_t socket_create()
{
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
#ifdef PLATFORM_UNIX
    if (sock < 0)
#endif
    {
        printf("socket_create: socket() failed.\n");
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

socket_t socket_connect(const char *host, i32 port)
{
    // TODO: Implement socket_connect
    return -1;
}

i32 socket_listen(socket_t socket, i32 port)
{
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

    if (listen(socket, SOMAXCONN) < 0)
    {
        printf("socket_listen: listen() failed.\n");
        return SOCKET_ERROR;
    }

    return SOCKET_NO_CONN;
}
