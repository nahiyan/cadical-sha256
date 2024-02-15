#include "propagate.hpp"
#include "1_bit/propagate.hpp"
#include "lru_cache.hpp"
#include "sha256.hpp"
#include "util.hpp"
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
cache::lru_cache<string, string> otf_prop_cache (5e6);

void load_prop_rules () {
  ifstream db ("prop_rules.db");
  if (!db) {
    printf ("Rules database not found. Can you ensure that 'prop_rules.db' "
            "exists in the current working directory?\n");
    exit (1);
  }

  int rules_count = 0;
#if IS_4BIT
  rules_count = load_4bit_prop_rules (db, otf_prop_cache);
#else
  rules_count = load_1bit_prop_rules (db, otf_prop_cache);
#endif

  printf ("Loaded %d rules\n", rules_count);
}
} // namespace SHA256