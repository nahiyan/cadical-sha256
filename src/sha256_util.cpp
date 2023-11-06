#include "sha256_util.hpp"

#include <cstdint>
#include <cstring>
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
} // namespace SHA256