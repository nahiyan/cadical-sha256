#ifndef _sha256_1_bit_propagate_hpp_INCLUDED
#define _sha256_1_bit_propagate_hpp_INCLUDED

#include "../lru_cache.hpp"
#include "../state.hpp"
#include <string>

using namespace std;

namespace SHA256 {
void custom_1bit_propagate (State &state, vector<int> &propagation_lits,
                            map<int, Reason> &reasons);
int load_1bit_prop_rules (ifstream &db,
                          cache::lru_cache<string, string> &cache);
} // namespace SHA256

#endif