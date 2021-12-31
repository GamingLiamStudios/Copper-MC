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

static const i32 SOCKET_ERROR   = -2;
static const i32 SOCKET_NO_CONN = -1;
static const i32 SOCKET_NO_DATA = 0;

socket_t socket_create();
void     socket_destroy(socket_t socket);

socket_t socket_connect(const char *host, i32 port);
i32      socket_listen(socket_t socket, i32 port);
