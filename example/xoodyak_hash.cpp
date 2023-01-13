#include "xoodyak.hpp"
#include <iostream>

// Example program demonstrating usage of Xoodyak Hash C++ API
//
// Compile it with
// g++ -std=c++20 -Wall -Wextra -O3 -I ./include example/xoodyak_hash.cpp
int
main()
{
  constexpr size_t msg_len = 64ul;

  uint8_t* msg = static_cast<uint8_t*>(std::malloc(msg_len));
  uint8_t* out = static_cast<uint8_t*>(std::malloc(xoodyak::DIGEST_LEN));

  xoodyak_utils::random_data(msg, msg_len);

  xoodyak::hash(msg, msg_len, out);

  using namespace xoodyak_utils;
  std::cout << "Message         : " << to_hex(msg, msg_len) << std::endl;
  std::cout << "Xoodyak Digest  : " << to_hex(out, xoodyak::DIGEST_LEN)
            << std::endl;

  std::free(msg);
  std::free(out);

  return EXIT_SUCCESS;
}
