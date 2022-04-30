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
}
