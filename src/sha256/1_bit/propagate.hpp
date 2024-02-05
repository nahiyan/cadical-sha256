#ifndef _sha256_1_bit_propagate_hpp_INCLUDED
#define _sha256_1_bit_propagate_hpp_INCLUDED

#include "../state.hpp"
#include <string>

using namespace std;

namespace SHA256 {
void custom_1bit_propagate (State &state, vector<int> &propagation_lits,
                            map<int, Reason> &reasons);
} // namespace SHA256

#endif