#include "xoodyak.hpp"
#include <cassert>
#include <iostream>

// Compile it with
// g++ -std=c++20 -Wall -Wextra -O3 -I ./include example/xoodyak_aead.cpp
int
main()
{
  constexpr size_t knt_len = 16ul;
  constexpr size_t ad_len = 32ul;
  constexpr size_t ct_len = 64ul;

  uint8_t* key = static_cast<uint8_t*>(std::malloc(knt_len));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(knt_len));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(knt_len));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(ad_len));
  uint8_t* txt = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ct_len));

  random_data(key, knt_len);
  random_data(nonce, knt_len);
  random_data(data, ad_len);
  random_data(txt, ct_len);

  bool f = false;

  xoodyak::encrypt(key, nonce, data, ad_len, txt, enc, ct_len, tag);
  f = xoodyak::decrypt(key, nonce, tag, data, ad_len, enc, dec, ct_len);

  assert(f);

  for (size_t i = 0; i < ct_len; i++) {
    assert((txt[i] ^ dec[i]) == 0u);
  }

  std::cout << "Xoodyak AEAD" << std::endl << std::endl;
  std::cout << "Key                : " << to_hex(key, knt_len) << std::endl;
  std::cout << "Nonce              : " << to_hex(nonce, knt_len) << std::endl;
  std::cout << "Associated Data    : " << to_hex(data, ad_len) << std::endl;
  std::cout << "Plain Text         : " << to_hex(txt, ct_len) << std::endl;
  std::cout << "Authentication Tag : " << to_hex(tag, knt_len) << std::endl;
  std::cout << "Encrypted Text     : " << to_hex(enc, ct_len) << std::endl;
  std::cout << "Decrypted Text     : " << to_hex(dec, ct_len) << std::endl;

  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(txt);
  std::free(enc);
  std::free(dec);

  return EXIT_SUCCESS;
}
