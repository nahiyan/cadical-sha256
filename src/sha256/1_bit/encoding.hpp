#ifndef _sha256_1_bit_encoding_hpp_INCLUDED
#define _sha256_1_bit_encoding_hpp_INCLUDED

#include "../../cadical.hpp"
#include <string>

using namespace std;

namespace SHA256 {
void add_1bit_variables (string line, CaDiCaL::Solver *&solver);
} // namespace SHA256

#endif