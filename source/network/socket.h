#pragma once
#include "util/platform.h"
#include "util/types.h"

#if defined(PLATFORM_WINDOWS)
#error Platform Windows is not supported yet.
// TODO: Implement Windows support
#elif defined(PLATFORM_UNIX)
#include <sys/socket.h>
#include <sys/select.h>
typedef i32 socket_t;
#else
#error Platform not supported.
#endif

static const i32 SOCKET_ERROR = -1;

socket_t socket_create();
void     socket_destroy(socket_t socket);

socket_t socket_connect(const char *host, i32 port);
i32      socket_listen(socket_t socket, i32 port);

#define socket_accept(socket)           accept(socket, NULL, NULL)
#define socket_send(socket, data, size) send(socket, data, size, 0)
#define socket_recv(socket, data, size) recv(socket, data, size, 0)
