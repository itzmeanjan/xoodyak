#pragma once
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#if defined __SSE2__ && USE_SSE2 != 0
// SSE intrinsics are defined on
// https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#techs=SSE_ALL
#include <emmintrin.h>
#pragma message("Using SSE2 for Xoodoo[12] Permutation")
#endif

// Xoodoo permutation which empowers Xoodyak cryptographic suite !
namespace xoodoo {

// Xoodoo permutation has 12 rounds; see abstract of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
constexpr size_t ROUNDS = 12ul;

// Xoodoo round constants; see table 2 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
constexpr uint32_t RC[ROUNDS] = { 0x00000058, 0x00000038, 0x000003c0,
                                  0x000000d0, 0x00000120, 0x00000014,
                                  0x00000060, 0x0000002c, 0x00000380,
                                  0x000000f0, 0x000001a0, 0x00000012 };

// Compile-time check to ensure that cyclic lane rotation factor ∈ {0, 1, 2}
consteval bool
check_lane_shift_factor(const int t)
{
  return (t == 0) || (t == 1) || (t == 2);
}

#if defined __SSE2__ && USE_SSE2 != 0

// Given a 128 -bit wide plane of Xoodoo permutation state ( each plane has 4
// lanes, each lane of 32 -bit ), this function cyclically shifts the plane such
// that bit at position (x, z) moves to (x+t, z+v), using SSE2 intrinsics.
//
// Note, at z = 0 bit index, least significant bit of each lane lives !
//
// See row 2 of table 1 in Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
//
// Find more about SSE intrinsics here
// https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#techs=SSE_ALL
template<const int t, const int v>
static inline __m128i
cyclic_shift(const __m128i plane)
  requires(check_lane_shift_factor(t))
{
  static_assert(v < 32, "Can't rotate 32 -bit integer by more than 31 -bits");

  if constexpr (t == 0) {
    // force compile-time branch evaluation
    static_assert(t == 0, "t must be = 0");

    const auto shl = _mm_slli_epi32(plane, v);
    const auto shr = _mm_srli_epi32(plane, 32 - v);

    return _mm_xor_si128(shl, shr);
  } else if constexpr (t == 1) {
    // force compile-time branch evaluation
    static_assert(t == 1, "t must be = 1");

    const auto shl = _mm_slli_epi32(plane, v);
    const auto shr = _mm_srli_epi32(plane, 32 - v);
    const auto rot = _mm_xor_si128(shl, shr);

    return _mm_shuffle_epi32(rot, 0b10010011);
  } else {
    // force compile-time branch evaluation
    static_assert(t == 2, "t must be = 2");

    const auto shl = _mm_slli_epi32(plane, v);
    const auto shr = _mm_srli_epi32(plane, 32 - v);
    const auto rot = _mm_xor_si128(shl, shr);

    return _mm_shuffle_epi32(rot, 0b01001110);
  }
}

#else

// Given a plane of Xoodoo permutation state ( each plane has 4 lanes, each lane
// of 32 -bit ), this function cyclically shifts the plane such that bit at
// position (x, z) moves to (x+t, z+v)
//
// Note, at z = 0 bit index, least significant bit of each lane lives !
//
// See row 2 of table 1 in Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
template<const int t, const int v>
static inline void
cyclic_shift(uint32_t* const plane)
  requires((check_lane_shift_factor(t)))
{
  if constexpr (t == 0) {
    // force compile-time branch evaluation
    static_assert(t == 0, "t must be = 0");

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 4
#endif
    for (size_t i = 0; i < 4; i++) {
      plane[i] = std::rotl(plane[i], v);
    }
  } else if constexpr (t == 1) {
    // force compile-time branch evaluation
    static_assert(t == 1, "t must be = 1");

    const auto tmp = plane[3];
    plane[3] = std::rotl(plane[2], v);
    plane[2] = std::rotl(plane[1], v);
    plane[1] = std::rotl(plane[0], v);
    plane[0] = std::rotl(tmp, v);

  } else {
    // force compile-time branch evaluation
    static_assert(t == 2, "t must be = 2");

#if defined __clang__
    // Following
    // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
    // Following
    // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 4
#endif
    for (size_t i = 0; i < 4; i++) {
      plane[i] = std::rotl(plane[i], v);
    }

    plane[0] ^= plane[2];
    plane[1] ^= plane[3];

    plane[2] ^= plane[0];
    plane[3] ^= plane[1];

    plane[0] ^= plane[2];
    plane[1] ^= plane[3];
  }
}

#endif

#if defined __SSE2__ && USE_SSE2 != 0

// θ step mapping of Xoodoo permutation, as described in algorithm 1 of Xoodyak
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
// implemented using SSE2 intrinsics s.t. whole state is represented using three
// 128 -bit SSE register.
static inline std::array<__m128i, 3>
theta(const std::array<__m128i, 3> state)
{
  const auto t0 = _mm_xor_si128(state[0], state[1]);
  const auto t1 = _mm_xor_si128(t0, state[2]);

  const auto p0 = cyclic_shift<1, 5>(t1);
  const auto p1 = cyclic_shift<1, 14>(t1);
  const auto e = _mm_xor_si128(p0, p1);

  return { _mm_xor_si128(state[0], e),
           _mm_xor_si128(state[1], e),
           _mm_xor_si128(state[2], e) };
}

#else

// θ step mapping of Xoodoo permutation, as described in algorithm 1 of Xoodyak
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
static inline void
theta(uint32_t* const state)
{
  uint32_t p0[4]{}; // must be zero-initialized !
  uint32_t p1[4];
  uint32_t e[4];

#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 3
#endif
  for (size_t i = 0; i < 12; i += 4) {
    p0[0] ^= state[i + 0];
    p0[1] ^= state[i + 1];
    p0[2] ^= state[i + 2];
    p0[3] ^= state[i + 3];
  }

  std::memcpy(p1, p0, sizeof(p0));

  cyclic_shift<1, 5>(p0);
  cyclic_shift<1, 14>(p1);

#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 4
#endif
  for (size_t i = 0; i < 4; i++) {
    e[i] = p0[i] ^ p1[i];
  }

#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 3
#endif
  for (size_t i = 0; i < 12; i += 4) {
    state[i + 0] ^= e[0];
    state[i + 1] ^= e[1];
    state[i + 2] ^= e[2];
    state[i + 3] ^= e[3];
  }
}

#endif

#if defined __SSE2__ && USE_SSE2 != 0

// ρ step mapping function of Xoodoo permutation, which is templated so that it
// can act as both `ρ_east` and `ρ_west`, implemented using SSE2 vector
// intrinsics.
//
// See algorithm 1 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
template<const size_t t1, const size_t v1, const size_t t2, const size_t v2>
static inline std::array<__m128i, 3>
rho(const std::array<__m128i, 3> state)
{
  return { state[0],
           cyclic_shift<t1, v1>(state[1]),
           cyclic_shift<t2, v2>(state[2]) };
}

#else

// ρ step mapping function of Xoodoo permutation, which is templated so that it
// can act as both `ρ_east` and `ρ_west`
//
// See algorithm 1 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
template<const size_t t1, const size_t v1, const size_t t2, const size_t v2>
static inline void
rho(uint32_t* const state)
{
  cyclic_shift<t1, v1>(state + 4);
  cyclic_shift<t2, v2>(state + 8);
}

#endif

#if defined __SSE2__ && USE_SSE2 != 0

// ι step mapping function of Xoodoo permutation, where single round constant is
// XORed into first lane ( x = 0 ) of first plane ( y = 0 ) of internal state,
// using SSE2 intrinsics.
//
// See algorithm 1 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
static inline __m128i
iota(const __m128i plane, const size_t r_idx)
{
  // Attempting to load from memory address aligned to 16 -bytes boundary, see
  // https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#techs=SSE_ALL&cats=Load&text=_mm_load_si128&ig_expand=4428
  alignas(16) const uint32_t tmp[4]{ RC[r_idx], 0u, 0u, 0u };
  const auto rc = _mm_load_si128((__m128i*)tmp);

  return _mm_xor_si128(plane, rc);
}

#else

// ι step mapping function of Xoodoo permutation, where round constant is XORed
// into first lane ( x = 0 ) of first plane ( y = 0 ) of internal state
//
// See algorithm 1 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
static inline void
iota(uint32_t* const state, const size_t r_idx)
{
  state[0] ^= RC[r_idx];
}

#endif

#if defined __SSE2__ && USE_SSE2 != 0

// χ step mapping function of Xoodoo permutation, which is a non-linear layer
// applied on state during permutation round, using SSE2 vector intrinsics.
//
// See algorithm 1 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
static inline std::array<__m128i, 3>
chi(const std::array<__m128i, 3> state)
{
  const auto b0 = _mm_andnot_si128(state[1], state[2]);
  const auto b1 = _mm_andnot_si128(state[2], state[0]);
  const auto b2 = _mm_andnot_si128(state[0], state[1]);

  return {
    _mm_xor_si128(state[0], b0),
    _mm_xor_si128(state[1], b1),
    _mm_xor_si128(state[2], b2),
  };
}

#else

// χ step mapping function of Xoodoo permutation, which is a non-linear layer
// applied on state during permutation round
//
// See algorithm 1 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
static inline void
chi(uint32_t* const state)
{
  uint32_t b0[4];
  uint32_t b1[4];
  uint32_t b2[4];

#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 4
#endif
  for (size_t i = 0; i < 4; i++) {
    b0[i] = ~state[4 + i] & state[8 + i];
  }

#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 4
#endif
  for (size_t i = 0; i < 4; i++) {
    b1[i] = ~state[8 + i] & state[i];
  }

#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 4
#endif
  for (size_t i = 0; i < 4; i++) {
    b2[i] = ~state[i] & state[4 + i];
  }

#if defined __clang__
  // Following
  // https://clang.llvm.org/docs/LanguageExtensions.html#extensions-for-loop-hint-optimizations

#pragma clang loop unroll(enable)
#pragma clang loop vectorize(enable)
#elif defined __GNUG__
  // Following
  // https://gcc.gnu.org/onlinedocs/gcc/Loop-Specific-Pragmas.html#Loop-Specific-Pragmas

#pragma GCC ivdep
#pragma GCC unroll 4
#endif
  for (size_t i = 0; i < 4; i++) {
    state[i] ^= b0[i];
    state[4 + i] ^= b1[i];
    state[8 + i] ^= b2[i];
  }
}

#endif

#if defined __SSE2__ && USE_SSE2 != 0

// Single round ( which specific round it is, denoted by `r_idx` ∈ [0, 12) ) of
// Xoodoo permutation, which applies following step mappings on state, in order
//
// - mixing layer θ
// - plane shifting ρ_west
// - addition of round constants ι
// - non-linear layer χ
// - plane shifting ρ_east
//
// using SSE2 intrinsics.
//
// See algorithm 1 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
static inline std::array<__m128i, 3>
round(const std::array<__m128i, 3> state, const size_t r_idx)
{
  const auto t0 = theta(state);
  const auto t1 = rho<1, 0, 0, 11>(t0);
  const auto t2 = iota(t1[0], r_idx);
  const auto t3 = chi({ t2, t1[1], t1[2] });
  const auto t4 = rho<0, 1, 2, 8>(t3);

  return t4;
}

#else

// Single round ( which specific round it is, denoted by `r_idx` ∈ [0, 12) ) of
// Xoodoo permutation, which applies following step mappings on state, in order
//
// - mixing layer θ
// - plane shifting ρ_west
// - addition of round constants ι
// - non-linear layer χ
// - plane shifting ρ_east
//
// See algorithm 1 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
static inline void
round(uint32_t* const state, const size_t r_idx)
{
  // mixing layer
  theta(state);
  // plane shifting
  rho<1, 0, 0, 11>(state);
  // add round constant
  iota(state, r_idx);
  // non-linear layer
  chi(state);
  // plane shifting
  rho<0, 1, 2, 8>(state);
}

#endif

#if defined __SSE2__ && USE_SSE2 != 0

// Xoodoo permutation function, where 12 rounds of Xoodoo round function is
// applied on internal state, using SSE2 intrinsics.
//
// See algorithm 1 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
static inline void
permute(uint32_t* const state)
{
  std::array<__m128i, 3> s_arr{ _mm_load_si128((__m128i*)(state + 0)),
                                _mm_load_si128((__m128i*)(state + 4)),
                                _mm_load_si128((__m128i*)(state + 8)) };

  for (size_t i = 0; i < ROUNDS; i++) {
    s_arr = round(s_arr, i);
  }

  _mm_store_si128((__m128i*)(state + 0), s_arr[0]);
  _mm_store_si128((__m128i*)(state + 4), s_arr[1]);
  _mm_store_si128((__m128i*)(state + 8), s_arr[2]);
}

#else

// Xoodoo permutation function, where 12 rounds of Xoodoo round function is
// applied on internal state
//
// See algorithm 1 of Xoodyak specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
static inline void
permute(uint32_t* const state)
{
  for (size_t i = 0; i < ROUNDS; i++) {
    round(state, i);
  }
}

#endif

}
