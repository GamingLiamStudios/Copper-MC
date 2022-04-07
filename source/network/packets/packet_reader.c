#include "packet_reader.h"

#include "network/varints.h"
#include "util/order.h"

#include <string.h>

void packet_reader_init(struct packet_reader *reader, struct packet *packet)
{
    if (!reader->buffer)
    {
        reader->buffer = malloc(sizeof(struct buffer));
        buffer_init(reader->buffer, packet->size);
    }
    buffer_clear(reader->buffer);
    buffer_append(reader->buffer, packet->data, packet->size);
    reader->offset = 0;
}
void packet_reader_destroy(struct packet_reader *reader)
{
    buffer_destroy(reader->buffer);
    free(reader->buffer);
}

// Basic Types
u8 packet_next_ubyte(struct packet_reader *reader)
{
    u8 data = reader->buffer->data[reader->offset];
    reader->offset += sizeof(u8);
    return data;
}
u16 packet_next_ushort(struct packet_reader *reader)
{
    union
    {
        u16 data;
        u8  bytes[sizeof(u16)];
    } u;
    u.bytes[1] = reader->buffer->data[reader->offset];
    u.bytes[0] = reader->buffer->data[reader->offset + 1];
    reader->offset += sizeof(u16);
    return u.data;
}
i32 packet_next_int(struct packet_reader *reader)
{
    // TODO: check if this actually benifits anyone
    union
    {
        i32 data;
        u8  bytes[sizeof(i32)];
    } u;
    u8 *bytes = reader->buffer->data + reader->offset;

    // This forces use of movbe on x86
    if (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
    {
        u.bytes[3] = bytes[0];
        u.bytes[2] = bytes[1];
        u.bytes[1] = bytes[2];
        u.bytes[0] = bytes[3];
    }
    else
        memcpy(u.bytes, bytes, sizeof(i32));

    reader->offset += sizeof(i32);
    return u.data;
}
i64 packet_next_long(struct packet_reader *reader)
{
    union
    {
        i64 data;
        u8  bytes[sizeof(i64)];
    } u;
    u8 *bytes = reader->buffer->data + reader->offset;

    // This forces use of movbe on x86
    if (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
    {
        u.bytes[7] = bytes[0];
        u.bytes[6] = bytes[1];
        u.bytes[5] = bytes[2];
        u.bytes[4] = bytes[3];
        u.bytes[3] = bytes[4];
        u.bytes[2] = bytes[5];
        u.bytes[1] = bytes[6];
        u.bytes[0] = bytes[7];
    }
    else
        memcpy(u.bytes, bytes, sizeof(i64));

    reader->offset += sizeof(i64);
    return u.data;
}
f32 packet_next_float(struct packet_reader *reader)
{
    i32 t = packet_next_int(reader);
    return *(f32 *) &t;
}
f64 packet_next_double(struct packet_reader *reader)
{
    i64 t = packet_next_long(reader);
    return *(f64 *) &t;
}

// Complex Types
i32 packet_next_varint(struct packet_reader *reader)
{
    i32 v = varint_decode(reader->buffer->data + reader->offset);
    reader->offset += varint_size(v);
    return v;
}
i64 packet_next_varlong(struct packet_reader *reader)
{
    i64 v = varlong_decode(reader->buffer->data + reader->offset);
    reader->offset += varint_size(v);
    return v;
}
void packet_next_bytes(struct packet_reader *reader, u8 *data, i32 size)
{
    memcpy(data, reader->buffer->data + reader->offset, size);
    reader->offset += size;
}
const u8 *packet_next_string(struct packet_reader *reader)
{
    i32 length = packet_next_varint(reader);

    u8 *string = (u8 *) malloc(length + 1);
    packet_next_bytes(reader, string, length);

    string[length] = L'\0';
    return string;
}