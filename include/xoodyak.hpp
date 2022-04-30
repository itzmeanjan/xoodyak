#pragma once
#include "cyclist.hpp"

namespace xoodyak {

// Xoodyak hash digest length in bytes
//
// For understanding why minimum 32 bytes output required, read corollary 1 in
// section 3.1 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
//
// You may also want to take a look at section 1.3.1 of above linked document
constexpr size_t DIGEST_LEN = 32ul;

// Xoodyak cryptographic hash function, as defined in section 1.3.1 of Xoodyak
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
//
// Given N -bytes input message, this function absorbs input into permutation
// state & squeezes out 32 -bytes as digest of consumed input bytes
static inline void
hash(const uint8_t* const __restrict msg, // N -bytes input message to be hashed
     const size_t m_len,                  // len(msg) | >= 0
     uint8_t* const __restrict out        // 32 -bytes digest of `msg`
)
{
  cyclist::phase_t ph = cyclist::phase_t::Up;
  uint32_t state[12] = { 0u };

  cyclist::absorb<cyclist::mode_t::Hash>(state, msg, m_len, &ph);
  cyclist::squeeze<cyclist::mode_t::Hash>(state, out, DIGEST_LEN, &ph);
}

}
