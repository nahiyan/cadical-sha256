#ifndef _sha256_propagate_hpp_INCLUDED
#define _sha256_propagate_hpp_INCLUDED

#include "sha256_2_bit.hpp"
#include <cstdint>
#include <string>
#include <vector>

enum FunctionId { ch, maj, xor3 };
// TODO: Integrate this
enum AdditionId { add_a, add_e, add_w, add_t };

using namespace std;

namespace SHA256 {
int64_t _int_diff (string word);
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
vector<string> derive_words (vector<string> words, int64_t constant);
void load_prop_rules (const char *path);
string propagate (int id, vector<string> input_words, string original);
void prop_with_int_diff (int equation_id, vector<string *> words);
pair<string, string> otf_add_propagate (string inputs, string outputs);
void otf_add_propagate (TwoBit &two_bit, vector<Word *> inputs,
                        vector<Word *> carries, vector<Word *> outputs);
} // namespace SHA256

#endif