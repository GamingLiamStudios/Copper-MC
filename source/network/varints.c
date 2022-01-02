#include "varints.h"

inline i32 varint_size(u32 value)
{
    if (value <= 0x7F) return 1;
    if (value <= 0x3FFF) return 2;
    if (value <= 0x1FFFFF) return 3;
    if (value <= 0xFFFFFFF) return 4;
    return 5;
}

inline void varint_encode(u8 *buffer, u64 value)
{
    do {
        u8 byte = value & 0x7F;
        value >>= 7;
        if (value != 0) byte |= 0x80;
        *buffer++ = byte;
    } while (value != 0);
}
inline i32 varint_decode(const u8 *buffer)
{
    u32 value = 0;
    u32 shift = 0;
    u8  byte  = 0;

    do {
        byte = *buffer++;
        value |= (u32) (byte & 0x7F) << shift;
        shift += 7;
    } while ((byte & 0x80));

    return value;
}

inline i64 varlong_decode(const u8 *buffer)
{
    u64 value = 0;
    u64 shift = 0;
    u8  byte  = 0;

    do {
        byte = *buffer++;
        value |= (u64) (byte & 0x7F) << shift;
        shift += 7;
    } while ((byte & 0x80));

    return value;
}
