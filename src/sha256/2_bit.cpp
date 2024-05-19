#include "1_bit/2_bit.hpp"
#include "lru_cache.hpp"
#include "propagate.hpp"
#include <cassert>
#include <climits>
#include <fstream>
#include <memory>
#include <set>
#include <sstream>

namespace SHA256 {
unordered_map<string, string> two_bit_rules;

cache::lru_cache<string, pair<string, string>> otf_2bit_cache (5e6);

} // namespace SHA256