#pragma once
#include "utils.hpp"
#include "xoodoo.hpp"
#include <algorithm>

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
down(uint32_t* const __restrict state,
     const uint8_t* const __restrict blk,
     const size_t b_len,
     phase_t* const __restrict ph)
{
  const size_t full_lane_cnt = b_len >> 2;
  const size_t part_lane_byt = b_len & 3ul;

  for (size_t i = 0; i < full_lane_cnt; i++) {
    const uint32_t lane = from_be_bytes(blk + (i << 2));
    state[i] ^= lane;
  }

  if (part_lane_byt == 3ul) {
    const size_t b_off = full_lane_cnt << 2;

    const uint32_t lane = (static_cast<uint32_t>(blk[b_off + 0]) << 24) |
                          (static_cast<uint32_t>(blk[b_off + 1]) << 16) |
                          (static_cast<uint32_t>(blk[b_off + 2]) << 8) | 0x01u;

    state[full_lane_cnt] ^= lane;
  } else if (part_lane_byt == 2ul) {
    const size_t b_off = full_lane_cnt << 2;

    const uint32_t lane = (static_cast<uint32_t>(blk[b_off + 0]) << 24) |
                          (static_cast<uint32_t>(blk[b_off + 1]) << 16) |
                          (0x01u << 8);

    state[full_lane_cnt] ^= lane;
  } else if (part_lane_byt == 1ul) {
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

  ph[0] = phase_t::Down;
}

// Internal function used in Cyclist mode of operation, which aims to produce
// N -bytes output
//
// See `Inside Cyclist` in section 2.2 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
//
// Also see algorithmic definition in algorithm 3 of aforelinked document
template<const mode_t m, const uint8_t color>
static inline void
up(uint32_t* const __restrict state,
   uint8_t* const __restrict blk,
   const size_t b_len,
   phase_t* const __restrict ph)
{
  if (m == mode_t::Keyed) {
    state[11] ^= static_cast<uint32_t>(color);
  }

  xoodoo::permute(state);

  const size_t full_lane_cnt = b_len >> 2;
  const size_t part_lane_byt = b_len & 3ul;

  for (size_t i = 0; i < full_lane_cnt; i++) {
    to_be_bytes(state[i], blk + (i << 2));
  }

  if (part_lane_byt == 3ul) {
    const size_t b_off = full_lane_cnt << 2;
    const uint32_t lane = state[full_lane_cnt];

    blk[b_off + 0] = static_cast<uint8_t>(lane >> 24);
    blk[b_off + 1] = static_cast<uint8_t>(lane >> 16);
    blk[b_off + 2] = static_cast<uint8_t>(lane >> 8);
  } else if (part_lane_byt == 2ul) {
    const size_t b_off = full_lane_cnt << 2;
    const uint32_t lane = state[full_lane_cnt];

    blk[b_off + 0] = static_cast<uint8_t>(lane >> 24);
    blk[b_off + 1] = static_cast<uint8_t>(lane >> 16);
  } else if (part_lane_byt == 1ul) {
    const size_t b_off = full_lane_cnt << 2;
    const uint32_t lane = state[full_lane_cnt];

    blk[b_off + 0] = static_cast<uint8_t>(lane >> 24);
  }

  ph[0] = phase_t::Up;
}

// Internal function used in Cyclist mode of operation, which absorbs N -many
// bytes into permutation state
//
// See second point of sub-section `Inside Cyclist` in section 2.2 of Xoodyak
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
//
// Also see algorithmic definition in algorithm 3 of aforelinked document
template<const mode_t m, const size_t rate, const uint8_t color>
static inline void
absorb_any(uint32_t* const __restrict state,    // 384 -bit permutation state
           const uint8_t* const __restrict msg, // input message to be absorbed
           const size_t m_len,                  // len(msg) | >= 0
           phase_t* const __restrict ph         // phase of cyclist mode
)
{
  // handling case where input string to `split(...)` is empty
  if (m_len == 0) {
    if (ph[0] != phase_t::Up) {
      up<m, 0x00>(state, nullptr, 0ul, ph);
    }

    down<m, color>(state, nullptr, 0ul, ph);
    return;
  }

  // handling case when input string to `split(...)` is non-empty
  const size_t full_blk_cnt = m_len / rate;
  const size_t part_blk_byt = m_len % rate;

  for (size_t i = 0; i < full_blk_cnt; i++) {
    const size_t b_off = i * rate;

    if (ph[0] != phase_t::Up) {
      up<m, 0x00>(state, nullptr, 0ul, ph);
    }

    if (i == 0ul) {
      down<m, color>(state, msg + b_off, rate, ph);
    } else {
      down<m, 0x00>(state, msg + b_off, rate, ph);
    }
  }

  // handling last message block, which might not have `rate` -many bytes
  if (part_blk_byt > 0ul) {
    const size_t b_off = full_blk_cnt * rate;

    if (ph[0] != phase_t::Up) {
      up<m, 0x00>(state, nullptr, 0ul, ph);
    }

    if (full_blk_cnt == 0ul) {
      down<m, color>(state, msg + b_off, part_blk_byt, ph);
    } else {
      down<m, 0x00>(state, msg + b_off, part_blk_byt, ph);
    }
  }
}

// Internal function used in Cyclist mode of operation, which produces N -bytes
// output, by squeezing those many bytes out of permutation state
//
// See second point of sub-section `Inside Cyclist` in section 2.2 of Xoodyak
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
//
// Also see algorithmic definition in algorithm 3 of aforelinked document
template<const mode_t m, const size_t rate, const uint8_t color>
static inline void
squeeze_any(uint32_t* const __restrict state, // 384 -bit permutation state
            uint8_t* const __restrict out,    // squeezed output to be written
            const size_t o_len,               // squeeze these many bytes
            phase_t* const __restrict ph      // phase of cyclist mode
)
{
  // in first round of squeeze `upto` -bytes will be
  // attempted to be squeezed out of state
  const size_t upto = std::min(o_len, rate);
  up<m, color>(state, out, upto, ph);

  // if no more bytes required ( happens when o_len <= rate ),
  // don't need any more squeezing
  if (o_len == upto) {
    return;
  }

  // when more bytes are required to be squeezed out of state
  size_t l = upto;
  while (l < o_len) {
    down<m, 0x00>(state, nullptr, 0ul, ph);

    const size_t tmp = std::min(o_len - l, rate);
    up<m, 0x00>(state, out + l, tmp, ph);
    l += tmp;
  }
}

}
