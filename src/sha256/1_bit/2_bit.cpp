#include "2_bit.hpp"
#include "../2_bit.hpp"
#include "../lru_cache.hpp"
#include "../state.hpp"
#include "../types.hpp"
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
void custom_1bit_block (State &state, TwoBit &two_bit) {
  for (int op_id = 0; op_id < 6; op_id++)
    for (int step_i = 0; step_i < state.order; step_i++)
      for (int bit_pos = 0; bit_pos < 32; bit_pos++) {
        auto &marked_op =
            state.marked_operations[(OperationId) op_id][step_i][bit_pos];
        if (!marked_op)
          continue;
        marked_op = false;

        auto &function = two_bit_functions[op_id];
        assert (op_id < op_add_w);

        // Construct the differential
        int input_size = two_bit_diff_sizes[op_id].first,
            output_size = two_bit_diff_sizes[op_id].second;
        auto &input_words = state.operations[step_i].inputs_by_op_id[op_id];
        auto &output_words =
            state.operations[step_i].outputs_by_op_id[op_id];
        string input_chars, output_chars;
        pair<vector<uint32_t>, vector<uint32_t>> ids;
        for (int i = 0; i < input_size; i++) {
          input_chars += *input_words[i].chars[bit_pos];
          ids.first.push_back (input_words[i].ids_f[bit_pos]);
          ids.second.push_back (input_words[i].ids_g[bit_pos]);
        }
        for (int i = 0; i < output_size; i++) {
          output_chars += output_words[i]->chars[bit_pos];
          ids.first.push_back (output_words[i]->ids_f[bit_pos]);
          ids.second.push_back (output_words[i]->ids_g[bit_pos]);
        }
        string all_chars = input_chars + output_chars;
        assert (input_size + output_size == ids.first.size ());
        assert (input_size + output_size == ids.second.size ());

        // Replace the equations for this particular spot
        auto &op_eqs = two_bit.eqs_by_op[op_id][step_i][bit_pos];
        op_eqs.clear ();
        auto &mask = masks_by_op_id[op_id];
        auto equations =
            otf_2bit_eqs (function, input_chars, output_chars, ids, mask);
        for (auto &equation : equations) {
          // Process inputs
          int const_zeroes_count = 0;
          for (int input_i = 0; input_i < input_size; input_i++) {
            if (input_chars[input_i] == '?')
              continue;

            bool is_const_zero = false;
            uint32_t ids[] = {input_words[input_i].ids_f[bit_pos],
                              input_words[input_i].ids_g[bit_pos],
                              input_words[input_i].char_ids[bit_pos]};
            if (ids[0] == state.zero_var_id) {
              const_zeroes_count++;
              is_const_zero = true;
              continue;
            }

            auto values = gc_values_1bit (input_chars[input_i]);
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
          for (int output_i = 0; output_i < output_size; output_i++) {
            if (output_chars[output_i] == '?')
              continue;

            // Ignore the high carry output if addends count < 4
            if (function == add_ && output_i == 0 &&
                (input_size - const_zeroes_count) < 4)
              continue;

            uint32_t ids[] = {output_words[output_i]->ids_f[bit_pos],
                              output_words[output_i]->ids_g[bit_pos],
                              output_words[output_i]->char_ids[bit_pos]};

            if (ids[0] == state.zero_var_id)
              continue;

            auto values = gc_values_1bit (output_chars[output_i]);
            for (int k = 0; k < 3; k++) {
              int lit = values[k] * ids[k];
              if (lit == 0)
                continue;
              assert (state.partial_assignment.get (ids[k]) ==
                      (lit > 0 ? LIT_TRUE : LIT_FALSE));
              equation.antecedent.push_back (-lit);
            }
          }
          assert (!equation.antecedent.empty ());
          op_eqs.push_back (equation);
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