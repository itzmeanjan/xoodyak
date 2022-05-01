#include "test_xoodyak_aead.hpp"
#include <iostream>

int
main()
{
  constexpr size_t min_ct_len = 0ul;
  constexpr size_t min_dt_len = 0ul;
  constexpr size_t max_ct_len = 32ul;
  constexpr size_t max_dt_len = 32ul;

  for (size_t i = min_ct_len; i < max_ct_len; i++) {
    for (size_t j = min_dt_len; j < max_dt_len; j++) {
      test_xoodyak::encrypt_decrypt(j, i, test_xoodyak::key);
      test_xoodyak::encrypt_decrypt(j, i, test_xoodyak::nonce);
      test_xoodyak::encrypt_decrypt(j, i, test_xoodyak::tag);
      test_xoodyak::encrypt_decrypt(j, i, test_xoodyak::data);
      test_xoodyak::encrypt_decrypt(j, i, test_xoodyak::enc);
      test_xoodyak::encrypt_decrypt(j, i, test_xoodyak::none);
    }
  }

  std::cout << "[test] Xoodyak AEAD works !" << std::endl;

  return EXIT_SUCCESS;
}
