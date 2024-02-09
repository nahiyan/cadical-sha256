#include "../propagate.hpp"
#include "../lru_cache.hpp"
#include "../state.hpp"
#include "../types.hpp"
#include "../util.hpp"
#include "propagate.hpp"
#include <cassert>
#include <fstream>
#include <sstream>

namespace SHA256 {
// Differential sizes
pair<int, int> prop_diff_sizes[10] = {{3, 1}, {3, 1}, {3, 1}, {3, 1},
                                      {3, 1}, {3, 1}, {6, 3}, {5, 3},
                                      {3, 3}, {7, 3}};
// Functions by operation IDs
vector<int> (*prop_functions[10]) (vector<int>) = {
    xor_, xor_, xor_, xor_, maj_, ch_, add_, add_, add_, add_};
void custom_1bit_propagate (State &state, vector<int> &propagation_lits,
                            map<int, Reason> &reasons) {
  int step_i = get<1> (state.last_marked_op);
  if (step_i == -1)
    return;
  auto op_id = get<0> (state.last_marked_op);
  auto bit_pos = get<2> (state.last_marked_op);
  state.last_marked_op = {op_s0, -1, -1};

  // Construct the differential
  int input_size = prop_diff_sizes[op_id].first,
      output_size = prop_diff_sizes[op_id].second;
  auto &input_words = state.operations[step_i].inputs_by_op_id[op_id];
  auto &output_words = state.operations[step_i].outputs_by_op_id[op_id];
  string input_chars, output_chars;
  vector<uint32_t> all_char_ids;
  for (int i = 0; i < input_size; i++) {
    input_chars += *input_words[i].chars[bit_pos];
    all_char_ids.push_back (input_words[i].char_ids[bit_pos]);
  }
  for (int i = 0; i < output_size; i++) {
    output_chars += output_words[i]->chars[bit_pos];
    all_char_ids.push_back (output_words[i]->char_ids[bit_pos]);
  }
  string all_chars = input_chars + output_chars;
  assert (input_size + output_size == all_char_ids.size ());

  // Propagate
  auto &function = prop_functions[op_id];
  string prop_output = otf_propagate (function, input_chars, output_chars);
  if (output_chars == prop_output)
    return;

  // Construct the antecedent with inputs
  Reason reason;
  int const_zeroes_count = 0;
  for (unsigned long x = 0; x < input_size; x++) {
    if (input_chars[x] == '?')
      continue;

    uint32_t ids[] = {input_words[x].ids_f[bit_pos],
                      input_words[x].ids_g[bit_pos],
                      input_words[x].char_ids[bit_pos]};

    // Count the const zeroes
    bool is_const_zero = false;
    if (ids[0] == state.zero_var_id) {
      const_zeroes_count++;
      is_const_zero = true;
      continue;
    }

    // Add lits
    auto table_values = gc_values_1bit (input_chars[x]);
    for (int y = 0; y < 3; y++) {
      auto &id = ids[y];
      int lit = table_values[y] * id;
      if (lit == 0)
        continue;
      assert (state.partial_assignment.get (id) ==
              (lit > 0 ? LIT_TRUE : LIT_FALSE));
      reason.antecedent.push_back (-lit);
    }
  }

  if (reason.antecedent.empty ())
    return;

  // Construct the antecedent with outputs
  vector<int> prop_lits;
  for (unsigned long x = 0; x < output_size; x++) {
    // Ignore the high carry output if addends can't add up to >= 4
    if (function == add_ && x == 0 && (input_size - const_zeroes_count) < 4)
      continue;

    uint32_t ids[] = {output_words[x]->ids_f[bit_pos],
                      output_words[x]->ids_g[bit_pos],
                      output_words[x]->char_ids[bit_pos]};

    if (ids[0] == state.zero_var_id)
      continue;

    auto table_values = gc_values_1bit (output_chars[x]);
    bool has_output_antecedent = false;
    {
      if (output_chars[x] != '?') {
        for (int y = 0; y < 3; y++) {
          auto &id = ids[y];
          int lit = table_values[y] * id;
          if (lit == 0)
            continue;
          reason.antecedent.push_back (-lit);
          assert (state.partial_assignment.get (id) ==
                  (lit > 0 ? LIT_TRUE : LIT_FALSE));
          has_output_antecedent = true;
        }
      }
    }
    assert (output_chars[x] != '?' ? has_output_antecedent : true);

    // TODO: Propagated char should have a higher score
    if (prop_output[x] == '?' || prop_output[x] == '#')
      continue;

    auto prop_table_values = gc_values_1bit (prop_output[x]);
    for (int y = 0; y < 3; y++) {
      auto &id = ids[y];
      if (prop_table_values[y] == 0)
        continue;
      int lit = prop_table_values[y] * id;
      if (lit == 0)
        continue;

      if (state.partial_assignment.get (id) != LIT_UNDEF)
        continue;

      propagation_lits.push_back (lit);
      prop_lits.push_back (lit);
    }
  }

  for (auto &lit : prop_lits)
    reasons[lit] = reason;
}

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
} // namespace SHA256