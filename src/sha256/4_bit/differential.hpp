#ifndef _sha256_4_bit_differential_hpp_INCLUDED
#define _sha256_4_bit_differential_hpp_INCLUDED

#include "../state.hpp"
#include "../types.hpp"
#include <string>

using namespace std;

namespace SHA256 {
void get_4bit_differential (OperationId op_id, int step_i, int bit_pos,
                            State &state, vector<Differential> &diffs);
} // namespace SHA256

#endif