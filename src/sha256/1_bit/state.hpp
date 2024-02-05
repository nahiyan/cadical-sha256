#ifndef _sha256_1_bit_state_hpp_INCLUDED
#define _sha256_1_bit_state_hpp_INCLUDED

#include <cinttypes>
#include <string>

using namespace std;

namespace SHA256 {
void refresh_1bit_char (uint8_t x, uint8_t x_, uint8_t diff, char &c);
} // namespace SHA256

#endif