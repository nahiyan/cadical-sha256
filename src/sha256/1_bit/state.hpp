#ifndef _sha256_1_bit_state_hpp_INCLUDED
#define _sha256_1_bit_state_hpp_INCLUDED

#include "../types.hpp"
#include <cinttypes>
#include <string>

using namespace std;

namespace SHA256 {
inline void refresh_1bit_char (uint8_t x, uint8_t x_, uint8_t diff,
                               char &c) {
  if (diff == LIT_FALSE && x == LIT_TRUE && x_ == LIT_TRUE)
    c = '1';
  else if (diff == LIT_FALSE && x == LIT_FALSE && x_ == LIT_FALSE)
    c = '0';
  else if (diff == LIT_TRUE && x == LIT_TRUE && x_ == LIT_FALSE)
    c = 'u';
  else if (diff == LIT_TRUE && x == LIT_FALSE && x_ == LIT_TRUE)
    c = 'n';
  else if (diff == LIT_FALSE)
    c = '-';
  else if (diff == LIT_TRUE)
    c = 'x';
  else
    c = '?';
}
} // namespace SHA256

#endif