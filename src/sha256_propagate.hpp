#ifndef _sha256_propagate_hpp_INCLUDED
#define _sha256_propagate_hpp_INCLUDED

#include "sha256.hpp"
#include <cstdint>
#include <string>
#include <vector>

#define IO_PROP_ADD2_ID 0
#define IO_PROP_CH_ID 1
#define IO_PROP_MAJ_ID 2
#define IO_PROP_XOR3_ID 3
#define IO_PROP_ADD3_ID 4
#define IO_PROP_ADD4_ID 5
#define IO_PROP_ADD5_ID 6
#define IO_PROP_ADD6_ID 7
#define IO_PROP_ADD7_ID 8

#define ADD_A_ID 0
#define ADD_E_ID 1
#define ADD_W_ID 2
#define ADD_T_ID 3

using namespace std;

namespace SHA256 {
int64_t _int_diff (char *chars);
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
void prop_with_int_diff (int equation_id, vector<string> words,
                         State &state, int step);
} // namespace SHA256

#endif