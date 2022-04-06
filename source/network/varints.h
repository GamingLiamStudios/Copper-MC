#pragma once

#include "util/types.h"

i32 varint_size(u64 value);

// TODO: Have this give a shit about the length
void varlong_encode(u8 *buffer, u64 value);
#define varint_encode(buffer, value) varlong_encode(buffer, value)

i64 varlong_decode(const u8 *buffer);
#define varint_decode(buffer) ((i32) varlong_decode(buffer))
