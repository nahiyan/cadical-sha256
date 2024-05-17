#ifndef _sha256_wordwise_propagate_hpp_INCLUDED
#define _sha256_wordwise_propagate_hpp_INCLUDED

#include "types.hpp"
#include <cstdint>
#include <string>
#include <vector>

using namespace std;

namespace SHA256 {
int64_t _word_diff (string chars);
int64_t adjust_constant (string word, int64_t constant,
                         vector<char> adjustable_gcs = {});
bool is_congruent (int64_t a, int64_t b, int64_t m);
bool _can_overflow (vector<string> vars_colwise, vector<uint8_t> bits);
vector<string> gen_vars (vector<string> words);
string brute_force (vector<string> var_cols, int64_t constant,
                    int64_t min_gt = -1);
vector<string> apply_grounding (vector<string> words,
                                vector<string> var_cols,
                                vector<char> values);
vector<string> wordwise_propagate (vector<string> words, int64_t constant);
void prop_with_word_diff (AdditionId equation_id, vector<string *> words);
} // namespace SHA256

#endif