#pragma once
#include "utils.hpp"
#include "xoodoo.hpp"

// Cyclist mode of operation, used in Xoodyak cryptographic suite !
namespace cyclist {

// Phase attribute, used for keeping track of whether last applied
// internal call was `up()` or `down()`
//
// See `Inside Cyclist` in section 2.2 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
enum phase_t
{
  Up,  // set when `up()` is invoked
  Down // set when `down()` is invoked
};

// Cyclist can be initialized in any of following two possible modes
//
// See section 2.2 ( read second paragraph ) of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
enum mode_t
{
  Hash, // non-keyed permutation
  Keyed // keyed permutation
};

// Internal function used in Cyclist mode of operation, which consumes N -bytes
//
// See `Inside Cyclist` in section 2.2 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
//
// Also see algorithmic definition in algorithm 3 of aforelinked document
template<const mode_t m, const uint8_t color>
static inline void
down(uint32_t* const state,
     const uint8_t* const blk,
     const size_t b_len,
     phase_t* const ph)
{
  const size_t full_lane_cnt = b_len >> 2;
  const size_t part_lane_cnt = b_len & 3ul;

  for (size_t i = 0; i < full_lane_cnt; i++) {
    const uint32_t lane = from_be_bytes(blk + (i << 2));
    state[i] ^= lane;
  }

  if (part_lane_cnt == 3ul) {
    const size_t b_off = full_lane_cnt << 2;

    const uint32_t lane = (static_cast<uint32_t>(blk[b_off + 0]) << 24) |
                          (static_cast<uint32_t>(blk[b_off + 1]) << 16) |
                          (static_cast<uint32_t>(blk[b_off + 2]) << 8) | 0x01u;

    state[full_lane_cnt] ^= lane;
  } else if (part_lane_cnt == 2ul) {
    const size_t b_off = full_lane_cnt << 2;

    const uint32_t lane = (static_cast<uint32_t>(blk[b_off + 0]) << 24) |
                          (static_cast<uint32_t>(blk[b_off + 1]) << 16) |
                          (0x01u << 8);

    state[full_lane_cnt] ^= lane;
  } else if (part_lane_cnt == 1ul) {
    const size_t b_off = full_lane_cnt << 2;

    const uint32_t tmp0 = (static_cast<uint32_t>(blk[b_off + 0]) << 24);
    const uint32_t tmp1 = (0x01u << 16);
    const uint32_t lane = tmp0 | tmp1;

    state[full_lane_cnt] ^= lane;
  } else {
    const uint32_t lane = (0x01u << 24);
    state[full_lane_cnt] ^= lane;
  }

  if (m == mode_t::Hash) {
    state[11] ^= static_cast<uint32_t>(color) & 0x01u;
  } else {
    state[11] ^= static_cast<uint32_t>(color);
  }

  *ph = phase_t::Down;
}

}
