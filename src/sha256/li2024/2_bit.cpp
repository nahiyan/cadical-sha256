#include "../lru_cache.hpp"
#include "../types.hpp"
#include "../util.hpp"
#include <cassert>
#include <fstream>
#include <sstream>

namespace SHA256 {
#if IS_LI2024

// Masks used for constructing 2-bit equations
string masks_by_op_id[NUM_OPS] = {"+++.", "+++.", "+++.",
                                  "+++.", "+++.", "+++."};
// Differential sizes
pair<int, int> two_bit_diff_sizes[NUM_OPS] = {{3, 1}, {3, 1}, {3, 1},
                                              {3, 1}, {3, 1}, {3, 1}};
// Functions by operation IDs
vector<int> (*two_bit_functions[NUM_OPS]) (vector<int>) = {xor_, xor_, xor_,
                                                           xor_, maj_, ch_};
#endif
} // namespace SHA256