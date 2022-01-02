#include "buffer.h"

#include <stdlib.h>
#include <string.h>

void buffer_init(struct buffer *buffer, u32 capacity)
{
    buffer->data     = malloc(capacity);
    buffer->size     = 0;
    buffer->capacity = capacity;
}
void buffer_destroy(struct buffer *buffer)
{
    free(buffer->data);
    buffer->size     = 0;
    buffer->capacity = 0;
}

inline void buffer_reserve(struct buffer *buffer, u32 capacity)
{
    if (buffer->capacity < capacity)
    {
        buffer->data     = realloc(buffer->data, capacity);
        buffer->capacity = capacity;
    }
}

inline void buffer_append(struct buffer *buffer, const void *data, u32 size)
{
    buffer_reserve(buffer, buffer->size + size);
    memcpy(buffer->data + buffer->size, data, size);
    buffer->size += size;
}

inline i32 buffer_read_socket(struct buffer *buffer, socket_t socket, u32 size)
{
    buffer_reserve(buffer, buffer->size + size);
    i32 err = socket_recv(socket, buffer->data + buffer->size, size);
    if (err > 0) buffer->size += size;
    return err;
}