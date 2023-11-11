#ifndef _sha256_util_hpp_INCLUDED
#define _sha256_util_hpp_INCLUDED

#include "NTL/vec_GF2.h"
#include <cstdint>
#include <string>
#include <vector>

using namespace std;

namespace SHA256 {
string rotate_word (string word, int amount, bool is_circular = true);
vector<uint32_t> rotate_word (vector<uint32_t> word, int amount,
                              bool is_circular = true);
int64_t e_mod (int64_t a, int64_t b);
NTL::GF2 sum (NTL::vec_GF2 &v);

int sum_dec_from_bin (NTL::vec_GF2 &v);
void print (vector<int> clause);
} // namespace SHA256

#endif