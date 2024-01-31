#include "sha256_util.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
#include <numeric>
#include <vector>

namespace SHA256 {
// Euclidean mod
int64_t e_mod (int64_t a, int64_t b) {
  int64_t r = a % b;
  return r >= 0 ? r : r + abs (b);
}

string rotate_word (string word, int amount, bool is_circular) {
  string rotated (word);
  int n = rotated.size ();
  int m = -1;
  if (!is_circular)
    m = abs (amount);
  for (int i = 0; i < n; i++) {
    // Shift
    if (m != -1 && i < m) {
      rotated[i] = '0';
      continue;
    }
    // Circular shift
    rotated[i] = word[e_mod (i + amount, n)];
  }

  return rotated;
}

vector<uint32_t> rotate_word (vector<uint32_t> word, int amount,
                              bool is_circular) {
  vector<uint32_t> rotated (word);
  int n = rotated.size ();
  int m = -1;
  if (!is_circular)
    m = abs (amount);
  for (int i = 0; i < n; i++) {
    // Shift
    if (m != -1 && i < m) {
      rotated[i] = 0;
      continue;
    }
    // Circular shift
    rotated[i] = word[e_mod (i + amount, n)];
  }

  return rotated;
}

NTL::GF2 sum (NTL::vec_GF2 &v) {
  NTL::GF2 sum = NTL::to_GF2 (0);
  for (int i = 0; i < v.length (); i++)
    sum += v[i];

  return sum;
}

// TODO: May require refactoring
int sum_dec_from_bin (NTL::vec_GF2 &v) {
  int sum = 0;
  for (int i = 0; i < v.length (); i++)
    sum += NTL::conv<int> (v[i]);

  return sum;
}

void print (vector<int> &vec) {
  for (auto &lit : vec)
    printf ("%d ", lit);
  printf ("\n");
}

void print (vector<uint32_t> &vec) {
  for (auto &lit : vec)
    printf ("%d ", lit);
  printf ("\n");
}

// Function to calculate the Cartesian product of multiple vectors of
// characters
vector<string> cartesian_product (vector<vector<char>> input) {
  vector<string> result;
  int numVectors = input.size ();
  vector<int> indices (numVectors, 0);

  while (true) {
    string currentProduct;
    for (int i = 0; i < numVectors; ++i)
      currentProduct.push_back (input[i][indices[i]]);

    result.push_back (currentProduct);

    int j = numVectors - 1;
    while (j >= 0 && indices[j] == int (input[j].size ()) - 1) {
      indices[j] = 0;
      j--;
    }

    if (j < 0)
      break;

    indices[j]++;
  }

  return result;
}

vector<string> cartesian_product (vector<char> input, int repeat) {
  vector<vector<char>> inputs;
  for (int i = 0; i < repeat; i++) {
    inputs.push_back (input);
  }
  return cartesian_product (inputs);
}

bool is_in (char x, vector<char> chars) {
  return find (chars.begin (), chars.end (), x) != chars.end ();
}
bool is_in (int x, vector<int> y) {
  return find (y.begin (), y.end (), x) != y.end ();
}

int sum (vector<int> addends) {
  int sum = 0;
  for (auto &addend : addends)
    sum += addend;
  return sum;
}

vector<int> add_ (vector<int> inputs) {
  int sum = accumulate (inputs.begin (), inputs.end (), 0);
  return {sum >> 2 & 1, sum >> 1 & 1, sum & 1};
}
vector<int> ch_ (vector<int> inputs) {
  int x = inputs[0], y = inputs[1], z = inputs[2];
  return {(x & y) ^ (x & z) ^ z};
}
vector<int> maj_ (vector<int> inputs) {
  int x = inputs[0], y = inputs[1], z = inputs[2];
  return {(x & y) ^ (y & z) ^ (x & z)};
}

vector<int> xor_ (vector<int> inputs) {
  int value = 0;
  for (auto &input : inputs) {
    value ^= input;
  }
  return {value};
}

uint8_t gc_values (char c) {
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

// Compare two characteristics by their scores
bool compare_gcs (char c1, char c2) {
  uint8_t scores[2];
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
uint64_t to_uint64_t (uint32_t x, uint32_t y) {
  return ((uint64_t) x << 32) | y;
}

// Store 2 uint32_t inside one uint64_t
void from_uint64_t (uint64_t z, uint32_t &x, uint32_t &y) {
  x = z >> 32;
  y = z & 0xffffffff;
}

} // namespace SHA256