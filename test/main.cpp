#include "test/test_xoodyak.hpp"
#include <iostream>

int
main()
{
  constexpr size_t min_ct_len = 0ul;
  constexpr size_t min_dt_len = 0ul;
  constexpr size_t max_ct_len = 64ul;
  constexpr size_t max_dt_len = 32ul;

  for (size_t i = min_ct_len; i < max_ct_len; i++) {
    for (size_t j = min_dt_len; j < max_dt_len; j++) {
      test_xoodyak::aead(j, i, test_xoodyak::mutate_t::key);
      test_xoodyak::aead(j, i, test_xoodyak::mutate_t::nonce);
      test_xoodyak::aead(j, i, test_xoodyak::mutate_t::tag);
      test_xoodyak::aead(j, i, test_xoodyak::mutate_t::data);
      test_xoodyak::aead(j, i, test_xoodyak::mutate_t::enc);
      test_xoodyak::aead(j, i, test_xoodyak::mutate_t::none);
    }
  }

  std::cout << "[test] Xoodyak AEAD works !" << std::endl;

  return EXIT_SUCCESS;
}
