#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

// Utility functions used in Xoodyak AEAD
namespace xoodyak_utils {

// Given a 32 -bit unsigned integer word, this routine swaps byte order and
// returns byte swapped 32 -bit word.
//
// Adapted from
// https://github.com/itzmeanjan/ascon/blob/151bd9f/include/utils.hpp#L13-L32
static inline constexpr uint32_t
bswap32(const uint32_t a)
{
#if defined __GNUG__
  return __builtin_bswap32(a);
#else
  return ((a & 0x000000ffu) << 24) | ((a & 0x0000ff00u) << 0x08) |
         ((a & 0x00ff0000u) >> 0x08) | ((a & 0xff000000u) >> 24);
#endif
}

// Given four little endian bytes, this function interprets it as a 32 -bit
// unsigned integer
static inline uint32_t
from_le_bytes(const uint8_t* const bytes)
{
  uint32_t word;
  std::memcpy(&word, bytes, 4);

  if constexpr (std::endian::native == std::endian::big) {
    word = bswap32(word);
  }

  return word;
}

// Given a 32 -bit unsigned integer, this function interprets it as a little
// endian byte array
static inline void
to_le_bytes(const uint32_t word, uint8_t* const bytes)
{
  if constexpr (std::endian::native == std::endian::big) {
    const uint32_t swapped = bswap32(word);
    std::memcpy(bytes, &swapped, 4);
  } else {
    std::memcpy(bytes, &word, 4);
  }
}

// Given a N -bytes array, this function converts it into hex string; taken from
// https://github.com/itzmeanjan/ascon/blob/6050ca9/include/utils.hpp#L325-L336
inline const std::string
to_hex(const uint8_t* const bytes, const size_t len)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < len; i++) {
    ss << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(bytes[i]);
  }
  return ss.str();
}

// Generate `len` -many random 8 -bit unsigned integers
inline void
random_data(uint8_t* const data, const size_t len)
{
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint8_t> dis;

  for (size_t i = 0; i < len; i++) {
    data[i] = dis(gen);
  }
}

}
