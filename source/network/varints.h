#pragma once

#include "util/types.h"

i32 varint_size(u32 value);

void varint_encode(u8 *buffer, u64 value);
i32  varint_decode(const u8 *buffer);

#define varlong_encode(buffer, value) varint_encode(buffer, value)
i64 varlong_decode(const u8 *buffer);
