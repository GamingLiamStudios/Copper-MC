#pragma once

#include "util/containers/buffer.h"
#include "util/types.h"
#include "packets.h"

#define PACKET_BUILDER_STR_MAX  (32767)
#define PACKET_BUILDER_CHAT_MAX (262144)

// Convert buffer to packet
void packet_builder_final(struct buffer *buffer, struct packet *packet);

// Basic Types
void packet_write_ubyte(struct buffer *buffer, u8 value);
void packet_write_ushort(struct buffer *buffer, u16 value);
void packet_write_int(struct buffer *buffer, i32 value);
void packet_write_long(struct buffer *buffer, i64 value);
void packet_write_float(struct buffer *buffer, f32 value);
void packet_write_double(struct buffer *buffer, f64 value);

// Complex Types
void packet_write_varint(struct buffer *buffer, i32 value);
void packet_write_varlong(struct buffer *buffer, i64 value);
void packet_write_buffer(struct buffer *buffer, struct buffer *bytes);
void packet_write_bytes(struct buffer *buffer, const u8 *data, u32 size);
void packet_write_string_ext(struct buffer *buffer, const u8 *value, u32 max_len);
// #define packet_write_chat(buffer, value) packet_write_string_ext(buffer,
// chat_to_string(value), PACKET_BUILDER_CHAT_MAX)

// UUID = u8 array of length 16
#define packet_write_uuid(buffer, uuid) packet_write_bytes(buffer, uuid, 16)

#define packet_write_byte(buffer, value)  packet_write_ubyte(buffer, (u8) (value))
#define packet_write_short(buffer, value) packet_write_ushort(buffer, (u16) (value))
#define packet_write_bool(buffer, value)  packet_write_ubyte(buffer, value)
#define packet_write_string(buffer, value) \
    packet_write_string_ext(buffer, value, PACKET_BUILDER_STR_MAX)
