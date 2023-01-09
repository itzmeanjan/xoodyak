#pragma once
#include "xoodyak.hpp"
#include <cassert>

// Ensure functional correctness of Xoodyak Authenticated Encryption with
// Associated Data ( AEAD )
namespace test_xoodyak {

// Choose which one to modify ( just a single bit flip ), before attempting
// decryption, to show that Xoodyak AEAD provides promised security properties
enum mutate_t
{
  key,   // secret key
  nonce, // public message nonce
  tag,   // authentication tag
  data,  // associated data
  enc,   // encrypted data
  none   // don't modify anything !
};

// Test Xoodyak AEAD Implementation by executing encrypt -> decrypt ->
// compare, on randomly generated input bytes, while also mutating ( a single
// bit flip ) decrypt routine input set to show that AEAD scheme works as
// expected
inline void
aead(const size_t dt_len, const size_t ct_len, const mutate_t m)
{
  constexpr size_t knt_len = 16ul;

  uint8_t* key = static_cast<uint8_t*>(std::malloc(knt_len));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(knt_len));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(knt_len));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dt_len));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ct_len));

  random_data(key, knt_len);
  random_data(nonce, knt_len);
  random_data(data, dt_len);
  random_data(text, ct_len);

  using namespace xoodyak;

  encrypt(key, nonce, data, dt_len, text, enc, ct_len, tag);

  // Mutate ( single bit flip ), when applicable !
  switch (m) {
    case mutate_t::key:
      key[0] ^= static_cast<uint8_t>(1);
      break;
    case mutate_t::nonce:
      nonce[0] ^= static_cast<uint8_t>(1);
      break;
    case mutate_t::tag:
      tag[0] ^= static_cast<uint8_t>(1);
      break;
    case mutate_t::data:
      if (dt_len > 0) {
        data[0] ^= static_cast<uint8_t>(1);
      }
      break;
    case mutate_t::enc:
      if (ct_len > 0) {
        enc[0] ^= static_cast<uint8_t>(1);
      }
      break;
    case mutate_t::none:
      // don't mutate anything --- ideal world !
      break;
  }

  const bool f = decrypt(key, nonce, tag, data, dt_len, enc, dec, ct_len);

  // authentication
  switch (m) {
    case mutate_t::key:
      assert(!f);
      break;
    case mutate_t::nonce:
      assert(!f);
      break;
    case mutate_t::tag:
      assert(!f);
      break;
    case mutate_t::data:
      if (dt_len > 0) {
        assert(!f);
      } else {
        assert(f);

        // byte-by-byte comparison to be sure that original plain text &
        // decrypted plain text bytes are actually same !
        for (size_t i = 0; i < ct_len; i++) {
          assert(text[i] == dec[i]);
        }
      }
      break;
    case mutate_t::enc:
      if (ct_len > 0) {
        assert(!f);
      } else {
        assert(f);

        // no byte-by-byte comparison required, because input plain text byte
        // array was empty !
      }
      break;
    case mutate_t::none:
      assert(f);

      // byte-by-byte comparison to be sure that original plain text & decrypted
      // plain text bytes are actually same !
      for (size_t i = 0; i < ct_len; i++) {
        assert(text[i] == dec[i]);
      }
      break;
  }

  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(text);
  std::free(enc);
  std::free(dec);
}

}
