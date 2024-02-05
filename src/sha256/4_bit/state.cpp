#include "../types.hpp"
#include <cinttypes>

namespace SHA256 {
void refresh_4bit_char (uint8_t *diff, char &c) {
  if (diff[1] == LIT_FALSE && diff[2] == LIT_FALSE && diff[3] == LIT_FALSE)
    c = '0';
  else if (diff[0] == LIT_FALSE && diff[2] == LIT_FALSE &&
           diff[3] == LIT_FALSE)
    c = 'u';
  else if (diff[0] == LIT_FALSE && diff[1] == LIT_FALSE &&
           diff[3] == LIT_FALSE)
    c = 'n';
  else if (diff[0] == LIT_FALSE && diff[1] == LIT_FALSE &&
           diff[2] == LIT_FALSE)
    c = '1';
  else if (diff[1] == LIT_FALSE && diff[2] == LIT_FALSE)
    c = '-';
  else if (diff[0] == LIT_FALSE && diff[3] == LIT_FALSE)
    c = 'x';
  else if (diff[2] == LIT_FALSE && diff[3] == LIT_FALSE)
    c = '3';
  else if (diff[1] == LIT_FALSE && diff[3] == LIT_FALSE)
    c = '5';
  else if (diff[3] == LIT_FALSE)
    c = '7';
  else if (diff[0] == LIT_FALSE && diff[2] == LIT_FALSE)
    c = 'A';
  else if (diff[2] == LIT_FALSE)
    c = 'B';
  else if (diff[0] == LIT_FALSE && diff[1] == LIT_FALSE)
    c = 'C';
  else if (diff[1] == LIT_FALSE)
    c = 'D';
  else if (diff[0] == LIT_FALSE)
    c = 'E';
  else
    c = '?';
}
} // namespace SHA256