#include "xoodyak.hpp"

// Thin C wrapper on top of underlying C++ implementation of Xoodyak
// cryptographic suite, as submitted in NIST LWC competition
//
// More https://csrc.nist.gov/Projects/Lightweight-Cryptography

// Function prototypes
extern "C"
{
  void hash(const uint8_t* const __restrict,
            const size_t,
            uint8_t* const __restrict);

  void encrypt(const uint8_t* const __restrict,
               const uint8_t* const __restrict,
               const uint8_t* const __restrict,
               const size_t,
               const uint8_t* const __restrict,
               uint8_t* const __restrict,
               const size_t,
               uint8_t* const __restrict);

  bool decrypt(const uint8_t* const __restrict,
               const uint8_t* const __restrict,
               const uint8_t* const __restrict,
               const uint8_t* const __restrict,
               const size_t,
               const uint8_t* const __restrict,
               uint8_t* const __restrict,
               const size_t);
}

// Function definitions
extern "C"
{

  // Given N ( >=0 ) -bytes input message string, this function computes 32
  // -bytes digest using Xoodyak cryptographic hash algorithm
  //
  // A thin wrapper to enforce usage of C ABI in generate shared library object,
  // which can be used via other language's Foreign Function Interface
  void hash(const uint8_t* const __restrict msg, // N -bytes input message
            const size_t m_len,                  // len(msg) | >= 0
            uint8_t* const __restrict digest     // 32 -bytes digest ( output )
  )
  {
    xoodyak::hash(msg, m_len, digest);
  }

  // Given 16 -bytes secret key, 16 -bytes public message nonce, N (>=0) -bytes
  // associated data & M (>=0) -bytes plain text, this routine computes M -bytes
  // cipher text along with 16 -bytes authentication tag, using Xoodyak AEAD
  // algorithm
  void encrypt(
    const uint8_t* const __restrict key,   // 128 -bit secret key
    const uint8_t* const __restrict nonce, // 128 -bit public message nonce
    const uint8_t* const __restrict data,  // N (>= 0) -bytes associated data
    const size_t dt_len,                   // len(data)
    const uint8_t* const __restrict text,  // M (>=0) -bytes plain text
    uint8_t* const __restrict cipher,      // M (>=0) -bytes cipher text
    const size_t ct_len,                   // len(text) == len(cipher)
    uint8_t* const __restrict tag          // 128 -bit authentication tag
  )
  {
    xoodyak::encrypt(key, nonce, data, dt_len, text, cipher, ct_len, tag);
  }

  // Given 16 -bytes secret key, 16 -bytes public message nonce, 16 -bytes
  // authentication tag, N (>=0) -bytes associated data & M (>=0) -bytes
  // encrypted text, this routine computes M -bytes decrypted text along with
  // boolean verification flag, using Xoodyak AEAD algorithm
  //
  // Before consuming decrypted bytes, ensure truth value in returned
  // verification flag !
  bool decrypt(
    const uint8_t* const __restrict key,    // 128 -bit secret key
    const uint8_t* const __restrict nonce,  // 128 -bit public message nonce
    const uint8_t* const __restrict tag,    // 128 -bit authentication tag
    const uint8_t* const __restrict data,   // N (>= 0) -bytes associated data
    const size_t dt_len,                    // len(data)
    const uint8_t* const __restrict cipher, // M (>=0) -bytes cipher text
    uint8_t* const __restrict text,         // M (>=0) -bytes plain text
    const size_t ct_len                     // len(cipher) == len(text)
  )
  {
    bool f = false;
    f = xoodyak::decrypt(key, nonce, tag, data, dt_len, cipher, text, ct_len);
    return f;
  }
}
