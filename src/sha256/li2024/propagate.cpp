#include "../lru_cache.hpp"
#include "../state.hpp"
#include "../util.hpp"
#include <cassert>
#include <fstream>
#include <sstream>

namespace SHA256 {
#if IS_LI2024
// Differential sizes
pair<int, int> prop_diff_sizes[NUM_OPS] = {
    {3, 3},
    {3, 3},
    {3, 3},
    {3, 3},
};
// Functions by operation IDs
vector<int> (*prop_functions[NUM_OPS]) (vector<int>) = {add_, add_, add_,
                                                        add_};
#endif
} // namespace SHA256