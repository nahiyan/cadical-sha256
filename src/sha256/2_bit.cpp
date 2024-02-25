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

// void load_two_bit_rules () {
//   ifstream db ("two_bit_rules.db");
//   if (!db) {
//     printf (
//         "Rules database not found. Can you ensure that 'two_bit_rules.db'
//         " "exists in the current working directory?\n");
//     exit (1);
//   }

//   int rules_count = 0;
// #if IS_4BIT
//   rules_count = load_4bit_two_bit_rules (db, otf_prop_cache);
// #else
//   rules_count = load_1bit_two_bit_rules (db, otf_2bit_cache);
// #endif

//   printf ("Loaded %d rules\n", rules_count);
// }

} // namespace SHA256