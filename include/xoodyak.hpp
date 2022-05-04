#pragma once
#include "cyclist.hpp"

// Xoodyak Cryptographic Suite --- Hash function, Authenticated Encryption with
// Associated Data ( read AEAD ) scheme
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

// Xoodyak Authenticated Encryption with Associated Data routine, which given 16
// -bytes secret key, 16 -bytes public message nonce, N -bytes associated data (
// never encryted ) & M -bytes plain text data ( it'll be encrypted ), computes
// M -bytes cipher text along with 16 -bytes authentication tag ( works as
// Message Authentication Code )
static inline void
encrypt(const uint8_t* const __restrict key,   // 128 -bit secret key
        const uint8_t* const __restrict nonce, // 128 -bit public message nonce
        const uint8_t* const __restrict data, // N (>= 0) -bytes associated data
        const size_t dt_len,                  // len(data)
        const uint8_t* const __restrict text, // M (>=0) -bytes plain text
        uint8_t* const __restrict cipher,     // M (>=0) -bytes cipher text
        const size_t ct_len,                  // len(text) == len(cipher)
        uint8_t* const __restrict tag         // 128 -bit authentication tag
)
{
  cyclist::phase_t ph = cyclist::phase_t::Up;
  uint32_t state[12] = { 0u };

  cyclist::absorb_key(state, key, nonce, &ph);
  cyclist::absorb<cyclist::mode_t::Keyed>(state, data, dt_len, &ph);
  cyclist::encrypt(state, text, cipher, ct_len, &ph);
  cyclist::squeeze<cyclist::mode_t::Keyed>(state, tag, 16ul, &ph);
}

// Xoodyak Verified Decryption with Associated Data routine, which given 16
// -bytes secret key, 16 -bytes public message nonce, 16 -bytes authentication
// tag, N -bytes associated data ( never encryted ) & M -bytes cipher text data,
// computes M -bytes deciphered text along with boolean flag denoting
// verification status
//
// Note, before consuming decrypted bytes ensure boolean flag is truth value
static inline bool
decrypt(const uint8_t* const __restrict key,   // 128 -bit secret key
        const uint8_t* const __restrict nonce, // 128 -bit public message nonce
        const uint8_t* const __restrict tag,   // 128 -bit authentication tag
        const uint8_t* const __restrict data, // N (>= 0) -bytes associated data
        const size_t dt_len,                  // len(data)
        const uint8_t* const __restrict cipher, // M (>=0) -bytes cipher text
        uint8_t* const __restrict text,         // M (>=0) -bytes plain text
        const size_t ct_len                     // len(cipher) == len(text)
)
{
  cyclist::phase_t ph = cyclist::phase_t::Up;
  uint32_t state[12] = { 0u };
  uint8_t tag_[16] = { 0u };

  cyclist::absorb_key(state, key, nonce, &ph);
  cyclist::absorb<cyclist::mode_t::Keyed>(state, data, dt_len, &ph);
  cyclist::decrypt(state, cipher, text, ct_len, &ph);
  cyclist::squeeze<cyclist::mode_t::Keyed>(state, tag_, 16ul, &ph);

  bool f = false;

#if defined __clang__
#elif defined __GNUG__
#pragma GCC unroll 16
#pragma GCC ivdep
#endif
  for (size_t i = 0; i < 16; i++) {
    f |= static_cast<bool>(tag[i] ^ tag_[i]);
  }

  return !f;
}

}
