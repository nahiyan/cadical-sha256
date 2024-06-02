#ifndef _sha256_li2024_state_hpp_INCLUDED
#define _sha256_li2024_state_hpp_INCLUDED

#include "../types.hpp"
#include <cinttypes>
#include <string>

using namespace std;

namespace SHA256 {
inline void refresh_li2024_char (uint8_t v, uint8_t d, char &c) {
  if (v == LIT_FALSE && d == LIT_FALSE)
    c = '-';
  else if (v == LIT_TRUE && d == LIT_TRUE)
    c = 'u';
  else if (v == LIT_FALSE && d == LIT_TRUE)
    c = 'n';
  else if (d == LIT_TRUE)
    c = 'x';
  else if (v == LIT_FALSE || d == LIT_FALSE)
    c = '-';
  else
    c = '?';
}
} // namespace SHA256

#endif