#ifndef _sha256_1_bit_differential_hpp_INCLUDED
#define _sha256_1_bit_differential_hpp_INCLUDED

#include "../state.hpp"
#include "../types.hpp"
#include <string>

using namespace std;

namespace SHA256 {
void get_1bit_differential (OperationId op_id, int step_i, int bit_pos,
                            State &state, vector<Differential_1bit> &diffs);
} // namespace SHA256

#endif