#include "sha256_util.hpp"
#include "sha256.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
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

void print (vector<int> vec) {
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
} // namespace SHA256