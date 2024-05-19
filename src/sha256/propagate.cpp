#include "lru_cache.hpp"
#include <cassert>
#include <cmath>
#include <cstring>
#include <fstream>
#include <numeric>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

using namespace std;

namespace SHA256 {
cache::lru_cache<string, pair<string, string>> otf_prop_cache (5e6);
} // namespace SHA256