#pragma once
#include <cstdint>

using size_t = std::size_t;

// Given four big endian bytes, this function interprets it as a 32 -bit
// unsigned integer
static inline uint32_t
from_be_bytes(const uint8_t* const bytes)
{
  return (static_cast<uint32_t>(bytes[0]) << 24) |
         (static_cast<uint32_t>(bytes[1]) << 16) |
         (static_cast<uint32_t>(bytes[2]) << 8) |
         (static_cast<uint32_t>(bytes[3]) << 0);
}

// Given a 32 -bit unsigned integer, this function interprets it as a big endian
// byte array
static inline void
to_be_bytes(const uint32_t word, uint8_t* const bytes)
{
#if defined __clang__
#pragma unroll 4
#endif
  for (size_t i = 0; i < 4; i++) {
    bytes[i] = static_cast<uint8_t>(word >> ((3ul - i) << 3));
  }
}
