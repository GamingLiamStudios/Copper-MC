#include "varints.h"

#define VARINT_SEGMENT  0x7F
#define VARINT_CONTINUE 0x80

inline i32 varint_size(u64 value)
{
    i32 size = 1;
    while (value > VARINT_SEGMENT)
    {
        value >>= 7;
        size++;
    }
    return size;
}

inline void varlong_encode(u8 *buffer, u64 value)
{
    do {
        u8 byte = value & VARINT_SEGMENT;
        value >>= 7;
        if (value != 0) byte |= VARINT_CONTINUE;
        *buffer++ = byte;
    } while (value != 0);
}

inline i64 varlong_decode(const u8 *buffer)
{
    u64 value = 0;
    u64 shift = 0;
    u8  byte  = 0;

    do {
        byte = *buffer++;
        value |= (u64) (byte & VARINT_SEGMENT) << shift;
        shift += 7;
    } while (byte & VARINT_CONTINUE);

    return value;
}
