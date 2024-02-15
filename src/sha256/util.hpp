#ifndef _sha256_util_hpp_INCLUDED
#define _sha256_util_hpp_INCLUDED

#include "NTL/vec_GF2.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <numeric>
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

vector<string> cartesian_product (vector<vector<char>> input);
vector<string> cartesian_product (vector<char> input, int repeat);

inline int sum (vector<int> addends) {
  int sum = 0;
  for (auto &addend : addends)
    sum += addend;
  return sum;
}

inline NTL::GF2 sum (NTL::vec_GF2 &v) {
  NTL::GF2 sum = NTL::to_GF2 (0);
  for (int i = 0; i < v.length (); i++)
    sum += v[i];

  return sum;
}

// TODO: May require refactoring
inline int sum_dec_from_bin (NTL::vec_GF2 &v) {
  int sum = 0;
  for (int i = 0; i < v.length (); i++)
    sum += NTL::conv<int> (v[i]);

  return sum;
}

inline void print (vector<int> &vec) {
  for (auto &lit : vec)
    printf ("%d ", lit);
  printf ("\n");
}

inline void print (vector<uint32_t> &vec) {
  for (auto &lit : vec)
    printf ("%d ", lit);
  printf ("\n");
}

inline int64_t e_mod (int64_t a, int64_t b) {
  int64_t r = a % b;
  return r >= 0 ? r : r + abs (b);
}

inline bool is_in (char x, vector<char> chars) {
  return find (chars.begin (), chars.end (), x) != chars.end ();
}
inline bool is_in (int x, vector<int> y) {
  return find (y.begin (), y.end (), x) != y.end ();
}

inline vector<int> add_ (vector<int> inputs) {
  int sum = accumulate (inputs.begin (), inputs.end (), 0);
  return {sum >> 2 & 1, sum >> 1 & 1, sum & 1};
}
inline vector<int> ch_ (vector<int> inputs) {
  int x = inputs[0], y = inputs[1], z = inputs[2];
  return {(x & y) ^ (x & z) ^ z};
}
inline vector<int> maj_ (vector<int> inputs) {
  int x = inputs[0], y = inputs[1], z = inputs[2];
  return {(x & y) ^ (y & z) ^ (x & z)};
}

inline vector<int> xor_ (vector<int> inputs) {
  int value = 0;
  for (auto &input : inputs) {
    value ^= input;
  }
  return {value};
}

inline uint8_t gc_values_4bit (char c) {
  uint8_t values = 0;
  if (c == '?')
    values = 15;
  else if (c == '-')
    values = 9;
  else if (c == 'x')
    values = 6;
  else if (c == '0')
    values = 1;
  else if (c == 'u')
    values = 2;
  else if (c == 'n')
    values = 4;
  else if (c == '1')
    values = 8;
  else if (c == '3')
    values = 3;
  else if (c == '5')
    values = 5;
  else if (c == '7')
    values = 7;
  else if (c == 'A')
    values = 10;
  else if (c == 'B')
    values = 11;
  else if (c == 'C')
    values = 12;
  else if (c == 'D')
    values = 13;
  else if (c == 'E')
    values = 14;
  else if (c == '#')
    values = 0;
  else
    assert (true);

  return values;
}

inline vector<int8_t> gc_values_1bit (char c) {
  switch (c) {
  case 'x':
    return {0, 0, 1};
  case '-':
    return {0, 0, -1};
  case 'u':
    return {1, -1, 0};
  case 'n':
    return {-1, 1, 0};
  case '1':
    return {1, 1, 0};
  case '0':
    return {-1, -1, 0};
  case '3':
    return {0, -1, 0};
  case '5':
    return {-1, 0, 0};
  case 'A':
    return {1, 0, 0};
  case 'C':
    return {0, 1, 0};
  default:
    return {0, 0, 0};
  }
}

// Compare two characteristics by their scores
inline bool compare_gcs (char c1, char c2) {
  auto get_score = [] (char c) -> uint8_t {
    if (c == '?')
      return 0;
    if (c == '7' || c == 'B' || c == 'D' || c == 'E')
      return 1;
    if (c == '-' || c == 'x' || c == '3' || c == '5' || c == 'A' ||
        c == 'C')
      return 2;
    if (c == '0' || c == 'u' || c == 'n' || c == '1')
      return 3;

    assert (c == '#');

    return 4;
  };

  return get_score (c2) > get_score (c1);
}

// Store 2 uint32_t inside one uint64_t
inline uint64_t to_uint64_t (uint32_t x, uint32_t y) {
  return ((uint64_t) x << 32) | y;
}

// Store 2 uint32_t inside one uint64_t
inline void from_uint64_t (uint64_t z, uint32_t &x, uint32_t &y) {
  x = z >> 32;
  y = z & 0xffffffff;
}
} // namespace SHA256

#endif