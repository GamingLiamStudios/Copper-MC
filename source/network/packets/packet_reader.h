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

// Basic Types
u8  packet_next_ubyte(struct packet_reader *reader);
u16 packet_next_ushort(struct packet_reader *reader);
i32 packet_next_int(struct packet_reader *reader);
i64 packet_next_long(struct packet_reader *reader);
f32 packet_next_float(struct packet_reader *reader);
f64 packet_next_double(struct packet_reader *reader);

// Complex Types
i32       packet_next_varint(struct packet_reader *reader);
i64       packet_next_varlong(struct packet_reader *reader);
void      packet_next_bytes(struct packet_reader *reader, u8 *data, i32 size);
const u8 *packet_next_string(struct packet_reader *reader);
// void packet_next_chat(reader, chat)
// uuid packet_next_uuid(reader)

#define packet_next_byte(reader)  ((i8) packet_next_ubyte(reader))
#define packet_next_short(reader) ((i16) packet_next_ushort(reader))
#define packet_next_bool(reader)  packet_next_byte(reader)
