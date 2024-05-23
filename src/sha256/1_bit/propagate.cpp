#include "../lru_cache.hpp"
#include "../state.hpp"
#include "../util.hpp"
#include <cassert>
#include <fstream>
#include <sstream>

namespace SHA256 {
#if !IS_LI2024
// Differential sizes
pair<int, int> prop_diff_sizes[NUM_OPS] = {{3, 1}, {3, 1}, {3, 1}, {3, 1},
                                           {3, 1}, {3, 1}, {6, 3}, {5, 3},
                                           {3, 3}, {7, 3}};
// Functions by operation IDs
vector<int> (*prop_functions[NUM_OPS]) (vector<int>) = {
    xor_, xor_, xor_, xor_, maj_, ch_, add_, add_, add_, add_};

int load_1bit_prop_rules (ifstream &db,
                          cache::lru_cache<string, string> &cache) {
  int count = 0;
  int id;
  string diff_inputs, diff_outputs;
  while (db >> id >> diff_inputs >> diff_outputs) {
    stringstream key_ss;
    string outputs;
    for (long x = 0; x < diff_outputs.size (); x++)
      outputs += '?';
    assert (outputs.size () == diff_outputs.size ());
    key_ss << id << " " << diff_inputs << " " << outputs;

    // TODO: Filter rules and add 1-bit based rules only

    cache.put (key_ss.str (), diff_outputs);
    count++;
  }

  return count;
}
#endif
} // namespace SHA256