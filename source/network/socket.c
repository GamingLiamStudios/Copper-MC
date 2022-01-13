#include "socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "logger/logger.h"

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
    if (socket != 0)
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
    // prevents 'socket_listen: bind() failed: Address already in use'
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &(int) { 1 }, sizeof(int)) < 0)
    {
        perror("socket_listen: setsockopt() failed");
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
        perror("socket_listen: bind() failed");
        return SOCKET_ERROR;
    }

    // Set non-blocking
    const int old_flags = fcntl(socket, F_GETFL, 0);
    if (old_flags < 0)
    {
        perror("socket_listen: fcntl() failed");
        return SOCKET_ERROR;
    }
    const int new_flags = fcntl(socket, F_SETFL, old_flags | O_NONBLOCK);
    if (new_flags < 0)
    {
        perror("socket_listen: fcntl() failed");
        return SOCKET_ERROR;
    }

    // Enable TCP_NODELAY
    int flag = 1;
    if (setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int)) < 0)
    {
        perror("socket_accept: setsockopt() failed");
        return SOCKET_ERROR;
    }

    // Start listening for new connections
    if (listen(socket, SOMAXCONN) < 0)
    {
        logger_log_level(LOG_LEVEL_ERROR, "socket_listen: listen() failed.\n");
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

    // Set non-blocking
    const int old_flags = fcntl(client, F_GETFL, 0);
    if (old_flags < 0)
    {
        perror("socket_accept: fcntl() failed");
        close(client);
        return SOCKET_ERROR;
    }
    const int new_flags = fcntl(client, F_SETFL, old_flags | O_NONBLOCK);
    if (new_flags < 0)
    {
        perror("socket_accept: fcntl() failed");
        close(client);
        return SOCKET_ERROR;
    }

    // Enable TCP_NODELAY
    int flag = 1;
    if (setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int)) < 0)
    {
        perror("socket_accept: setsockopt() failed");
        close(client);
        return SOCKET_ERROR;
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
        if (errno != EWOULDBLOCK)
        {
            logger_log_level(LOG_LEVEL_ERROR, "socket_recv: Connection closed.\n");
            return SOCKET_NO_CONN;
        }
        else
            return SOCKET_NO_DATA;
    }

    return bytes;
}

i32 socket_send(socket_t socket, const u8 *buffer, i32 buffer_size)
{
    i32 bytes = send(socket, buffer, buffer_size, 0);
    if (bytes < 0)
    {
        if (errno == EWOULDBLOCK)
            return socket_send(socket, buffer, buffer_size);
        else if (errno == EMSGSIZE)
        {
            while ((bytes = socket_send(socket, buffer, buffer_size / 2)) < 0)
            {
                if (errno != EWOULDBLOCK)
                {
                    perror("socket_send: send() failed");
                    return SOCKET_ERROR;
                }
            }

            while ((bytes = socket_send(socket, buffer + buffer_size / 2, buffer_size / 2)) < 0)
            {
                if (errno != EWOULDBLOCK)
                {
                    perror("socket_send: send() failed");
                    return SOCKET_ERROR;
                }
            }
        }
        else
        {
            perror("socket_send: send() failed");
            return SOCKET_ERROR;
        }
    }

    if (bytes != buffer_size) bytes = socket_send(socket, buffer + bytes, buffer_size - bytes);

    return bytes;
}
