#include "../propagate.hpp"
#include "../lru_cache.hpp"
#include "../state.hpp"
#include "../types.hpp"
#include "../util.hpp"
#include "differential.hpp"
#include "propagate.hpp"
#include <cassert>
#include <fstream>
#include <sstream>

namespace SHA256 {
void custom_1bit_propagate (State &state, vector<int> &propagation_lits,
                            map<int, Reason> &reasons) {
  auto &step_i = get<1> (state.last_marked_op);
  if (get<1> (state.last_marked_op) == -1)
    return;
  auto &op_id = get<0> (state.last_marked_op);
  auto &bit_pos = get<2> (state.last_marked_op);
  vector<Differential_1bit> diffs;
  get_1bit_differential (op_id, step_i, bit_pos, state, diffs);
  state.last_marked_op = {op_s0, -1, -1};
  if (diffs.empty ())
    return;
  for (auto &diff : diffs) {
    Reason reason;
    assert (!diff.inputs.empty ());

    string prop_output =
        otf_propagate (diff.function, diff.inputs, diff.outputs);
    if (diff.outputs == prop_output)
      continue;

    // Construct the antecedent with inputs
    int const_zeroes_count = 0;
    for (unsigned long x = 0; x < diff.inputs.size (); x++) {
      if (diff.inputs[x] == '?')
        continue;

      // Count the const zeroes
      bool is_const_zero = false;
      if (diff.ids.first[x][0] == state.zero_var_id) {
        const_zeroes_count++;
        is_const_zero = true;
        continue;
      }

      // Add lits
      for (int y = 0; y < 3; y++) {
        auto &id = diff.ids.first[x][y];
        auto &table_value = diff.table_values.first[x][y];
        int lit = table_value * id;
        if (lit == 0)
          continue;
        assert (state.partial_assignment.get (id) ==
                (lit > 0 ? LIT_TRUE : LIT_FALSE));
        reason.antecedent.push_back (-lit);
      }
    }

    if (reason.antecedent.empty ())
      continue;

    // Construct the antecedent with outputs
    vector<int> prop_lits;
    for (unsigned long x = 0; x < diff.outputs.size (); x++) {
      // Ignore the high carry output if addends can't add up to >= 4
      if (diff.function == add_ && x == 0 &&
          (diff.inputs.size () - const_zeroes_count) < 4)
        continue;

      if (diff.ids.second[x][0] == state.zero_var_id)
        continue;

      auto &table_values = diff.table_values.second[x];
      bool has_output_antecedent = false;
      {
        if (diff.outputs[x] != '?') {
          for (int y = 0; y < 3; y++) {
            auto &id = diff.ids.second[x][y];
            auto &table_value = table_values[y];
            int lit = table_value * id;
            if (lit == 0)
              continue;
            reason.antecedent.push_back (-lit);
            assert (state.partial_assignment.get (id) ==
                    (lit > 0 ? LIT_TRUE : LIT_FALSE));
            has_output_antecedent = true;
          }
        }
      }
      assert (diff.outputs[x] != '?' ? has_output_antecedent : true);

      // TODO: Propagated char should have a higher score
      if (prop_output[x] == '?' || prop_output[x] == '#')
        continue;

      auto prop_table_values = gc_values_1bit (prop_output[x]);
      for (int y = 0; y < 3; y++) {
        auto &id = diff.ids.second[x][y];
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

    diff.outputs = prop_output;

    for (auto &lit : prop_lits)
      reasons[lit] = reason;
  }

  if (!propagation_lits.empty ())
    return;
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