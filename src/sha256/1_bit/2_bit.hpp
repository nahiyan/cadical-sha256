#ifndef _sha256_1_bit_2_bit_hpp_INCLUDED
#define _sha256_1_bit_2_bit_hpp_INCLUDED

#include "../lru_cache.hpp"
#include "../state.hpp"
#include <string>

using namespace std;

namespace SHA256 {
void derive_2bit_equations_1bit (State &state, list<Equation> &equations);
int load_1bit_two_bit_rules (ifstream &db,
                             cache::lru_cache<string, string> &cache);
} // namespace SHA256

#endif