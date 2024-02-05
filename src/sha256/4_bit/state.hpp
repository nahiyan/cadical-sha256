#ifndef _sha256_4_bit_state_hpp_INCLUDED
#define _sha256_4_bit_state_hpp_INCLUDED

#include <cinttypes>
#include <string>

using namespace std;

namespace SHA256 {
void refresh_4bit_char (uint8_t *diff, char &c);
} // namespace SHA256

#endif