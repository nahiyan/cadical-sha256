#include "2_bit.hpp"
#include "../lru_cache.hpp"
#include <cassert>
#include <fstream>
#include <sstream>

namespace SHA256 {
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