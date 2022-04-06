#include "packet_reader.h"
#include "util/order.h"

void packet_reader_init(struct packet_reader *reader, struct packet *packet)
{
    buffer_init(reader->buffer, packet->size);
    buffer_append(reader->buffer, packet->data, packet->size);
    reader->offset = 0;
}
void packet_reader_destroy(struct packet_reader *reader)
{
    buffer_destroy(reader->buffer);
}
void packet_reader_reuse(struct packet_reader *reader, struct packet *packet)
{
    buffer_clear(reader->buffer);
    buffer_append(reader->buffer, packet->data, packet->size);
    reader->offset = 0;
}

// Basic Types
u8 packet_reader_read_ubyte(struct packet_reader *reader)
{
    u8 data = reader->buffer->data[reader->offset];
    reader->offset += sizeof(u8);
    return data;
}
u16 packet_reader_read_ushort(struct packet_reader *reader)
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
i32 packet_reader_read_int(struct packet_reader *reader)
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
i64 packet_reader_read_long(struct packet_reader *reader)
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
f32 packet_reader_read_float(struct packet_reader *reader)
{
    i32 t = packet_reader_read_int(reader);
    return *(f32 *) &t;
}
f64 packet_reader_read_double(struct packet_reader *reader)
{
    i64 t = packet_reader_read_long(reader);
    return *(f64 *) &t;
}

// Complex Types
i32 packet_reader_read_varint(struct packet_reader *reader)
{
    i32 v = varint_decode(reader->buffer->data + reader->offset);
    reader->offset += varint_size(v);
    return v;
}
i64 packet_reader_read_varlong(struct packet_reader *reader)
{
    i64 v = varlong_decode(reader->buffer->data + reader->offset);
    reader->offset += varlong_size(v);
    return v;
}
void packet_reader_read_bytes(struct packet_reader *reader, u8 *data, u32 size)
{
    memcpy(data, reader->buffer->data + reader->offset, size);
    reader->offset += size;
}
const wchar_t *packet_reader_read_string(struct packet_reader *reader)
{
    i32 length = packet_reader_read_varint(reader);
    if (length == 0) return L"";

    // TODO: Optimize this
    wchar_t *string = (wchar_t *) malloc(sizeof(wchar_t) * (length + 1));
    for (int i = 0; i < length; i++)
    {
        u8 f = packet_reader_read_ubyte(reader);
        if(!(f & 0x80)
        {
            string[i] = f;
            continue;
        }
        
        u8 s = 2;
        u32 code = f;
        while((f <<= 1) & 0x80)
        {
            code <<= 6;
            code |= packet_reader_read_ubyte(reader) & 0x3F;
            s++;
        }
        code &= 0xFFFFFFFF >> (32 - ((s - 2) * 6 + (8 - s)));
    }

    string[length] = L'\0';
    return string;
}