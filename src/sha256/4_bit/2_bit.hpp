#ifndef _sha256_4_bit_2_bit_hpp_INCLUDED
#define _sha256_4_bit_2_bit_hpp_INCLUDED

#include "../state.hpp"
#include <string>

using namespace std;

namespace SHA256 {
void custom_4bit_block (State &state, TwoBit &two_bit);
} // namespace SHA256

#endif