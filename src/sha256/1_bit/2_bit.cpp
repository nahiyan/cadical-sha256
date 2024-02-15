#include "../lru_cache.hpp"
#include "../util.hpp"
#include <cassert>
#include <fstream>
#include <sstream>

namespace SHA256 {
// Masks used for constructing 2-bit equations
string masks_by_op_id[10] = {"+++.",   "+++.",      "+++.",      "+++.",
                             "+++.",   "+++.",      ".+.+....+", "+......+",
                             "++...+", "+...+....+"};
// Differential sizes
pair<int, int> two_bit_diff_sizes[10] = {{3, 1}, {3, 1}, {3, 1}, {3, 1},
                                         {3, 1}, {3, 1}, {6, 3}, {5, 3},
                                         {3, 3}, {7, 3}};
// Functions by operation IDs
vector<int> (*two_bit_functions[10]) (vector<int>) = {
    xor_, xor_, xor_, xor_, maj_, ch_, add_, add_, add_, add_};

int load_1bit_two_bit_rules (ifstream &db,
                             cache::lru_cache<string, string> &cache) {
  int count = 0;
  int id;
  string diff_inputs, diff_outputs, diff_pairs;
  while (db >> id >> diff_inputs >> diff_outputs >> diff_pairs) {
    stringstream key_ss;
    key_ss << id << " " << diff_inputs << " " << diff_outputs;

    // TODO: Filter rules and add 1-bit based rules only

    cache.put (key_ss.str (), diff_pairs);
    count++;
  }

  return count;
}
} // namespace SHA256