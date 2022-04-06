#pragma once

#include "util/containers/buffer.h"
#include "util/types.h"
#include "packets.h"

#define PACKET_BUILDER_STR_MAX  (32767)
#define PACKET_BUILDER_CHAT_MAX (262144)

// Convert buffer to packet
inline void packet_builder_final(struct buffer *buffer, struct packet *packet, i32 packet_id);

// Basic Types
inline void packet_builder_write_ubyte(struct buffer *buffer, u8 value);
inline void packet_builder_write_ushort(struct buffer *buffer, u16 value);
inline void packet_builder_write_int(struct buffer *buffer, i32 value);
inline void packet_builder_write_long(struct buffer *buffer, i64 value);
inline void packet_builder_write_float(struct buffer *buffer, f32 value);
inline void packet_builder_write_double(struct buffer *buffer, f64 value);

// Complex Types
inline void packet_builder_write_varint(struct buffer *buffer, i32 value);
inline void packet_builder_write_varlong(struct buffer *buffer, i64 value);
inline void packet_builder_write_bytes(struct buffer *buffer, struct buffer *bytes);
inline void
  packet_builder_write_string_ext(struct buffer *buffer, const wchar_t *value, u32 max_len);
// #define packet_builder_write_chat(buffer, value) packet_builder_write_string_ext(buffer,
// chat_to_string(value), PACKET_BUILDER_CHAT_MAX)
// define packet_builder_write_uuid(buffer, uuid) packet_builder_write_bytes(buffer,
// uuid_to_bytes(uuid))

#define packet_builder_write_byte(buffer, value)  packet_builder_write_ubyte(buffer, (u8) (value))
#define packet_builder_write_short(buffer, value) packet_builder_write_ushort(buffer, (u16) (value))
#define packet_builder_write_bool(buffer, value)  packet_builder_write_ubyte(buffer, value)
#define packet_builder_write_string(buffer, value) \
    packet_builder_write_string_ext(buffer, value, PACKET_BUILDER_STR_MAX)
