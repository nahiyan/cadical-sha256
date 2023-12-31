#ifndef _sha256_util_hpp_INCLUDED
#define _sha256_util_hpp_INCLUDED

#include "NTL/vec_GF2.h"
#include <cstdint>
#include <string>
#include <vector>

using namespace std;

namespace SHA256 {
class Timer {
  clock_t start_time;
  // Target to add the delta to
  clock_t *target;

public:
  Timer (clock_t *target) {
    start_time = clock ();
    this->target = target;
  }
  ~Timer () { *this->target += clock () - start_time; }
};

string rotate_word (string word, int amount, bool is_circular = true);
vector<uint32_t> rotate_word (vector<uint32_t> word, int amount,
                              bool is_circular = true);
int64_t e_mod (int64_t a, int64_t b);
NTL::GF2 sum (NTL::vec_GF2 &v);
int sum (vector<int> addends);

int sum_dec_from_bin (NTL::vec_GF2 &v);
void print (vector<int> &clause);
vector<string> cartesian_product (vector<vector<char>> input);
vector<string> cartesian_product (vector<char> input, int repeat);
bool is_in (char x, vector<char> chars);
bool is_in (int x, vector<int> y);
vector<int> add_ (vector<int> inputs);
vector<int> ch_ (vector<int> inputs);
vector<int> maj_ (vector<int> inputs);
vector<int> xor_ (vector<int> inputs);
} // namespace SHA256

#endif