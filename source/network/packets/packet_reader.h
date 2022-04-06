#pragma once

#include "util/types.h"
#include "util/containers/buffer.h"
#include "packets.h"

struct packet_reader
{
    struct buffer *buffer;
    u32            offset;
};

void packet_reader_init(struct packet_reader *reader, struct packet *packet);
void packet_reader_destroy(struct packet_reader *reader);
void packet_reader_reuse(struct packet_reader *reader, struct packet *packet);

// Basic Types
inline u8  packet_reader_read_ubyte(struct packet_reader *reader);
inline u16 packet_reader_read_ushort(struct packet_reader *reader);
inline i32 packet_reader_read_int(struct packet_reader *reader);
inline i64 packet_reader_read_long(struct packet_reader *reader);
inline f32 packet_reader_read_float(struct packet_reader *reader);
inline f64 packet_reader_read_double(struct packet_reader *reader);

// Complex Types
inline i32          packet_reader_read_varint(struct packet_reader *reader);
inline i64          packet_reader_read_varlong(struct packet_reader *reader);
inline void         packet_reader_read_bytes(struct packet_reader *reader, u8 *data, i32 size);
inline const wchar *packet_reader_read_string(struct packet_reader *reader);
// void packet_reader_read_chat(reader, chat)
// uuid packet_reader_read_uuid(reader)

#define packet_reader_read_byte(reader)  ((i8) packet_reader_read_ubyte(reader))
#define packet_reader_read_short(reader) ((i16) packet_reader_read_ushort(reader))
#define packet_reader_read_bool(reader)  packet_reader_read_byte(reader)
