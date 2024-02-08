#include "2_bit.hpp"
#include "../2_bit.hpp"
#include "../lru_cache.hpp"
#include "../state.hpp"
#include "../types.hpp"
#include "../util.hpp"
#include "differential.hpp"
#include <cassert>
#include <fstream>
#include <sstream>

namespace SHA256 {
void custom_1bit_block (State &state, TwoBit &two_bit) {
  for (int op_id = 0; op_id < 10; op_id++)
    for (int step_i = 0; step_i < state.order; step_i++)
      for (int bit_pos = 0; bit_pos < 32; bit_pos++) {
        auto &marked_op =
            state.marked_operations[(OperationId) op_id][step_i][bit_pos];
        if (!marked_op)
          continue;
        vector<Differential_1bit> diffs;
        get_1bit_differential ((OperationId) op_id, step_i, bit_pos, state,
                               diffs);
        marked_op = false;
        for (auto &diff : diffs) {
          auto &op_id = diff.operation_id;
          auto &step_i = diff.step_index;
          auto &pos = diff.bit_pos;

          // Set the base IDs vector
          vector<uint32_t> base_ids;
          for (auto &ids : diff.ids.first)
            base_ids.push_back (ids[2]);
          for (auto &ids : diff.ids.second)
            base_ids.push_back (ids[2]);
          assert (diff.ids.first.size () + diff.ids.second.size () ==
                  base_ids.size ());

          // Replace the equations for this particular spot
          auto &op_eqs = two_bit.eqs_by_op[op_id][step_i][pos];
          op_eqs.clear ();
          auto equations = otf_2bit_eqs (diff.function, diff.inputs,
                                         diff.outputs, base_ids, diff.mask);
          string all_chars = diff.inputs + diff.outputs;
          for (auto &equation : equations) {
            // Process inputs
            int const_zeroes_count = 0;
            for (int input_i = 0; input_i < int (diff.ids.first.size ());
                 input_i++) {
              if (diff.inputs[input_i] == '?')
                continue;

              bool is_const_zero = false;
              auto &ids = diff.ids.first[input_i];
              if (ids[0] == state.zero_var_id) {
                const_zeroes_count++;
                is_const_zero = true;
                continue;
              }

              auto values = gc_values_1bit (diff.inputs[input_i]);
              for (int k = 0; k < 3; k++) {
                uint32_t &id = ids[k];
                int lit = values[k] * id;
                if (lit == 0)
                  continue;
                assert (state.partial_assignment.get (id) ==
                        (lit > 0 ? LIT_TRUE : LIT_FALSE));
                equation.antecedent.push_back (-lit);
              }
            }

            // Process outputs
            for (int output_i = 0; output_i < int (diff.ids.second.size ());
                 output_i++) {
              if (diff.outputs[output_i] == '?')
                continue;

              // Ignore the high carry output if addends count < 4
              if (diff.function == add_ && output_i == 0 &&
                  (diff.inputs.size () - const_zeroes_count) < 4)
                continue;

              if (diff.ids.second[output_i][0] == state.zero_var_id)
                continue;

              auto values = gc_values_1bit (diff.outputs[output_i]);
              for (int k = 0; k < 3; k++) {
                auto &id = diff.ids.second[output_i][k];
                int lit = values[k] * id;
                if (lit == 0)
                  continue;
                assert (state.partial_assignment.get (id) ==
                        (lit > 0 ? LIT_TRUE : LIT_FALSE));
                equation.antecedent.push_back (-lit);
              }
            }
            assert (!equation.antecedent.empty ());
            op_eqs.push_back (equation);
          }
        }
      }
}

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