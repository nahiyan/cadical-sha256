#include "util.hpp"

#include <algorithm>
#include <cassert>
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
#include <numeric>
#include <vector>

namespace SHA256 {

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

} // namespace SHA256