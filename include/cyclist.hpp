#pragma once
#include "utils.hpp"
#include "xoodoo.hpp"
#include <algorithm>
#include <cstring>

// Cyclist mode of operation, used in Xoodyak cryptographic suite !
namespace cyclist {

// Phase attribute, used for keeping track of whether last applied
// internal call was `up()` or `down()`
//
// See `Inside Cyclist` in section 2.2 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
enum class phase_t : uint8_t
{
  Up,  // set when `up()` is invoked
  Down // set when `down()` is invoked
};

// Cyclist can be initialized in any of following two possible modes
//
// See section 2.2 ( read second paragraph ) of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
enum class mode_t : uint8_t
{
  Hash, // non-keyed permutation
  Keyed // keyed permutation
};

// Absorb/ squeeze rate in hash mode of Xoodyak, see definition 2 in section 2.3
// of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
constexpr size_t R_Hash = 16ul;

// Absorb rate in keyed mode of Xoodyak, see definition 2 in section 2.3
// of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
constexpr size_t R_Kin = 44ul;

// Squeeze rate in keyed mode of Xoodyak, see definition 2 in section 2.3
// of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
constexpr size_t R_Kout = 24ul;

// Rate in keyed mode of Xoodyak, when permutation state is transformed in a
// irreversible way by invoking `ratchet(...)`, ensuring forward secrecy; see
// definition 2 in section 2.3 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
constexpr size_t l_ratchet = 16ul;

// Color value used for domain seperation in hash mode of `absorb()`
constexpr uint8_t Absorb_Color_Hash = 0x01u;

// Color value used for domain seperation in keyed mode of `absorb()`
constexpr uint8_t Absorb_Color_Keyed = 0x03u;

// Color value used for domain seperation in `absorb_key()`
constexpr uint8_t AbsorbKey_Color = 0x02u;

// Color value used for domain seperation in `crypt()`
constexpr uint8_t Crypt_Color = 0x80u;

// Color value used for domain seperation in `squeeze()`
constexpr uint8_t Squeeze_Color = 0x40u;

// Color value used for domain seperation in `squeeze_key()`
constexpr uint8_t SqueezeKey_Color = 0x20u;

// Color value used for domain seperation in `ratchet()`
constexpr uint8_t Ratchet_Color = 0x10u;

// Color value used when no domain seperation is required
constexpr uint8_t Zero_Color = 0x00u;

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
    const uint32_t lane = from_le_bytes(blk + (i << 2));
    state[i] ^= lane;
  }

  const size_t b_off = full_lane_cnt << 2;
  uint32_t lane = 0x01u << (part_lane_byt << 3);

  for (size_t i = 0; i < part_lane_byt; i++) {
    lane |= static_cast<uint32_t>(blk[b_off + i]) << (i << 3);
  }

  state[full_lane_cnt] ^= lane;

  state[11] ^= static_cast<uint32_t>(color) << 24;
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
  if constexpr (m == mode_t::Keyed) {
    state[11] ^= static_cast<uint32_t>(color) << 24;
  }

  xoodoo::permute(state);

  const size_t full_lane_cnt = b_len >> 2;
  const size_t part_lane_byt = b_len & 3ul;

  for (size_t i = 0; i < full_lane_cnt; i++) {
    to_le_bytes(state[i], blk + (i << 2));
  }

  const size_t b_off = full_lane_cnt << 2;
  const uint32_t lane = state[full_lane_cnt];

  for (size_t i = 0; i < part_lane_byt; i++) {
    blk[b_off + i] = static_cast<uint8_t>(lane >> (i << 3));
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
  if (ph[0] != phase_t::Up) {
    up<m, Zero_Color>(state, nullptr, 0ul, ph);
  }

  const size_t read = std::min(rate, m_len);
  down<m, color>(state, msg, read, ph);

  size_t boff = read;
  while (boff < m_len) {
    up<m, Zero_Color>(state, nullptr, 0ul, ph);

    const size_t read = std::min(rate, m_len - boff);
    down<m, Zero_Color>(state, msg + boff, read, ph);

    boff += read;
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
    down<m, Zero_Color>(state, nullptr, 0ul, ph);

    const size_t tmp = std::min(o_len - l, rate);
    up<m, Zero_Color>(state, out + l, tmp, ph);
    l += tmp;
  }
}

// Internal function used in Cyclist mode of operation, which absorbs 128 -bit
// secret key & 128 -bit public message nonce into permutation state
//
// See algorithmic definition in algorithm 3 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
static inline void
absorb_key(
  uint32_t* const __restrict state,      // 384 -bit permutation state
  const uint8_t* const __restrict key,   // 128 -bit secret key
  const uint8_t* const __restrict nonce, // 128 -bit public message nonce
  phase_t* const __restrict ph           // phase of cyclist mode of operation
)
{
  // temporary buffer for contiguous storage of
  // `key || nonce || len(nonce)`
  uint8_t msg[33];

  std::memcpy(msg, key, 16);
  std::memcpy(msg + 16, nonce, 16);
  msg[32] = static_cast<uint8_t>(16);

  absorb_any<mode_t::Keyed, R_Kin, AbsorbKey_Color>(state, msg, 33ul, ph);
}

// Internal function used in Cyclist mode of operation, which encrypts plain
// text/ decrypts cipher text ( based on template parameter's truthness )
//
// See algorithmic definition in algorithm 3 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
template<const bool decrypt>
static inline void
crypt(uint32_t* const __restrict state,   // 384 -bit permutation state
      const uint8_t* const __restrict in, // N -bytes input message
      uint8_t* const __restrict out,      // N -bytes output message
      const size_t io_len,                // len(in) == len(out) == N | N >= 0
      phase_t* const __restrict ph        // phase of cyclist mode of operation
)
{
  // compulsory part of crypt routine, doesn't matter whether io_len != 0
  const size_t read = std::min(R_Kout, io_len);
  up<mode_t::Keyed, Crypt_Color>(state, out, read, ph);

  for (size_t i = 0; i < read; i++) {
    out[i] ^= in[i];
  }

  if constexpr (decrypt) {
    // force compile-time branch evaluation
    static_assert(decrypt, "Must be decrypting !");
    down<mode_t::Keyed, Zero_Color>(state, out, read, ph);
  } else {
    // force compile-time branch evaluation
    static_assert(!decrypt, "Must be encrypting !");
    down<mode_t::Keyed, Zero_Color>(state, in, read, ph);
  }

  size_t boff = read;
  while (boff < io_len) {
    const size_t read = std::min(R_Kout, io_len - boff);
    up<mode_t::Keyed, Zero_Color>(state, out + boff, read, ph);

    for (size_t i = 0; i < read; i++) {
      out[boff + i] ^= in[boff + i];
    }

    if constexpr (decrypt) {
      // force compile-time branch evaluation
      static_assert(decrypt, "Must be decrypting !");
      down<mode_t::Keyed, Zero_Color>(state, out + boff, read, ph);
    } else {
      // force compile-time branch evaluation
      static_assert(!decrypt, "Must be encrypting !");
      down<mode_t::Keyed, Zero_Color>(state, in + boff, read, ph);
    }

    boff += read;
  }
}

// External function used in Cyclist mode of operation, which consumes N -bytes
// input string, by absorbing those many bytes into permutation state
//
// Also see algorithmic definition in algorithm 2 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
template<const mode_t m>
static inline void
absorb(uint32_t* const __restrict state,
       const uint8_t* const __restrict msg,
       const size_t m_len,
       phase_t* const __restrict ph)
{
  if constexpr (m == mode_t::Hash) {
    // force compile-time branch evaluation
    static_assert(m == mode_t::Hash, "Must be hashing mode !");
    absorb_any<m, R_Hash, Absorb_Color_Hash>(state, msg, m_len, ph);
  } else if constexpr (m == mode_t::Keyed) {
    // force compile-time branch evaluation
    static_assert(m == mode_t::Keyed, "Must be keyed mode !");
    absorb_any<m, R_Kin, Absorb_Color_Keyed>(state, msg, m_len, ph);
  }
}

// External function used in Cyclist mode of operation, which produces N -bytes
// output string, by squeezing those many bytes out of permutation state
//
// Also see algorithmic definition in algorithm 2 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
template<const mode_t m>
static inline void
squeeze(uint32_t* const __restrict state,
        uint8_t* const __restrict out,
        const size_t o_len,
        phase_t* const __restrict ph)
{
  if constexpr (m == mode_t::Hash) {
    // force compile-time branch evaluation
    static_assert(m == mode_t::Hash, "Must be hashing mode !");
    squeeze_any<m, R_Hash, Squeeze_Color>(state, out, o_len, ph);
  } else if constexpr (m == mode_t::Keyed) {
    // force compile-time branch evaluation
    static_assert(m == mode_t::Keyed, "Must be keyed mode !");
    squeeze_any<m, R_Kout, Squeeze_Color>(state, out, o_len, ph);
  }
}

// External function used in Cyclist mode of operation, which encrypts N -bytes
// plain text input message
//
// Also see algorithmic definition in algorithm 2 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
static inline void
encrypt(
  uint32_t* const __restrict state,     // 384 -bit permutation state
  const uint8_t* const __restrict text, // N (>= 0) -bytes plain text to encrypt
  uint8_t* const __restrict cipher,     // N (>= 0) -bytes encrypted text
  const size_t ct_len,                  // len(text) == len(cipher) == N
  phase_t* const __restrict ph          // phase of cyclist mode of operation
)
{
  crypt<false>(state, text, cipher, ct_len, ph);
}

// External function used in Cyclist mode of operation, which decrypts N -bytes
// cipher text input message back to plain text
//
// Also see algorithmic definition in algorithm 2 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
static inline void
decrypt(uint32_t* const __restrict state,       // 384 -bit permutation state
        const uint8_t* const __restrict cipher, // N (>=0) -bytes encrypted text
        uint8_t* const __restrict text,         // N (>=0) -bytes decrypted text
        const size_t ct_len,                    // len(cipher) == len(text) == N
        phase_t* const __restrict ph            // phase of cyclist mode
)
{
  crypt<true>(state, cipher, text, ct_len, ph);
}

}
