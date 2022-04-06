#include "packet_builder.h"
#include "network/varints.h"
#include "logger/logger.h"

#include <stdlib.h>
#include <string.h>

void packet_builder_final(struct buffer *buffer, struct packet *packet, i32 packet_id)
{
    packet->packet_id = packet_id;
    packet->size      = buffer_size(buffer);
    if (packet->data == NULL) packet->data = malloc(packet->size);
    memcpy(packet->data, buffer->data, packet->size);
}

void packet_builder_write_ubyte(struct buffer *buffer, u8 value)
{
    buffer_append_u8(buffer, value);
}
void packet_builder_write_ushort(struct buffer *buffer, u16 value)
{
    buffer_append_u8(buffer, (u8) (value >> 8));
    buffer_append_u8(buffer, (u8) (value & 0xFF));
}
void packet_builder_write_int(struct buffer *buffer, i32 value)
{
    u32 v = (u32) value;
    buffer_append_u8(buffer, (u8) (v >> 24));
    buffer_append_u8(buffer, (u8) (v >> 16));
    buffer_append_u8(buffer, (u8) (v >> 8));
    buffer_append_u8(buffer, (u8) (v & 0xFF));
}
void packet_builder_write_long(struct buffer *buffer, i64 value)
{
    u64 v = (u64) value;
    buffer_append_u8(buffer, (u8) (v >> 56));
    buffer_append_u8(buffer, (u8) (v >> 48));
    buffer_append_u8(buffer, (u8) (v >> 40));
    buffer_append_u8(buffer, (u8) (v >> 32));
    buffer_append_u8(buffer, (u8) (v >> 24));
    buffer_append_u8(buffer, (u8) (v >> 16));
    buffer_append_u8(buffer, (u8) (v >> 8));
    buffer_append_u8(buffer, (u8) (v & 0xFF));
}
void packet_builder_write_float(struct buffer *buffer, f32 value)
{
    i32 v = *(i32 *) &value;
    packet_builder_write_int(buffer, v);
}
void packet_builder_write_double(struct buffer *buffer, f64 value)
{
    i64 v = *(i64 *) &value;
    packet_builder_write_long(buffer, v);
}

void packet_builder_write_varint(struct buffer *buffer, i32 value)
{
    u8 t[5];
    varint_encode(t, value);
    buffer_append(buffer, t, varint_size(value));
}
void packet_builder_write_varlong(struct buffer *buffer, i64 value)
{
    u8 t[10];
    varlong_encode(t, value);
    buffer_append(buffer, t, varint_size(value));
}
void packet_builder_write_bytes(struct buffer *buffer, struct buffer *bytes)
{
    buffer_append(buffer, bytes->data, bytes->size);
}
void packet_builder_write_string_ext(struct buffer *buffer, const wchar *value, u32 max_len)
{
    u32 len = wcslen(value);
    if (len > max_len)
    {
        len = max_len;
        logger_log_level(
          LOG_LEVEL_WARN,
          "packet_builder_write_string: truncating string to %u characters",
          len);
    }

    packet_builder_write_varint(buffer, len);

    u8  b;
    u32 chr;
    for (int i = 0; i < len; i++)
    {
        chr = value[i];
        if (chr < 0x80)
        {
            packet_builder_write_ubyte(buffer, (u8) (chr & 0x7F));
            continue;
        }

        if (chr <= 0x07FF)
            b = 5;
        else if (chr <= 0xFFFF)
            b = 4;
        else if (chr <= 0x10FFFF)
            b = 3;

        packet_builder_write_ubyte(buffer, (u8) ((0xFE << b) | (chr >> ((6 - b) * 6))));    // B1
        for (int j = 6 - b; j > 0; j--)                                                     // B2-4
            packet_builder_write_ubyte(buffer, (u8) (0x80 | ((chr >> (j - 1) * 6) & 0x3F)));
    }
}