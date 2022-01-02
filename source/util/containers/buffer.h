#pragma once

#include "util/types.h"
#include "network/socket.h"

struct buffer
{
    u8 *data;
    u32 size;
    u32 capacity;
};

void buffer_init(struct buffer *buffer, u32 capacity);
void buffer_destroy(struct buffer *buffer);

void buffer_reserve(struct buffer *buffer, u32 capacity);
#define buffer_clear(buffer) (buffer)->size = 0;

#define buffer_size(buffer)     ((buffer)->size)
#define buffer_capacity(buffer) ((buffer)->capacity)

void buffer_append(struct buffer *buffer, const void *data, u32 size);
i32  buffer_read_socket(struct buffer *buffer, socket_t socket, u32 size);
