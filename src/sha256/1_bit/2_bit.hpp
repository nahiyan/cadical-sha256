#ifndef _sha256_1_bit_2_bit_hpp_INCLUDED
#define _sha256_1_bit_2_bit_hpp_INCLUDED

#include "../2_bit.hpp"
#include "../lru_cache.hpp"
#include "../state.hpp"
#include "../util.hpp"
#include <string>

using namespace std;

namespace SHA256 {
extern string masks_by_op_id[10];
extern pair<int, int> two_bit_diff_sizes[10];
extern vector<int> (*two_bit_functions[10]) (vector<int>);

inline void derive_2bit_equations_1bit (State &state,
                                        list<Equation> &equations,
                                        Stats &stats) {
  for (auto &level : state.prop_markings_trail) {
    for (auto marking_it = level.begin (); marking_it != level.end ();
         marking_it++) {
      auto op_id = marking_it->op_id;
      auto step_i = marking_it->step_i;
      auto bit_pos = marking_it->bit_pos;

#if !TWO_BIT_ADD_DIFFS
      if (op_id >= op_add_w)
        continue;
#endif
      marking_it = level.erase (marking_it);

      auto &function = two_bit_functions[op_id];
#if !TWO_BIT_ADD_DIFFS
      assert (op_id < op_add_w);
#endif

      // Construct the differential
      int input_size = two_bit_diff_sizes[op_id].first,
          output_size = two_bit_diff_sizes[op_id].second;
      auto &input_words = state.operations[step_i].inputs_by_op_id[op_id];
      auto &output_words = state.operations[step_i].outputs_by_op_id[op_id];
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
      assert (input_size + output_size == int (ids.first.size ()));
      assert (input_size + output_size == int (ids.second.size ()));

      // Replace the equations for this particular spot
      auto &mask = masks_by_op_id[op_id];
      auto new_equations = otf_2bit_eqs (function, input_chars,
                                         output_chars, ids, mask, &stats);
      // Add the antecedent for the equations
      for (auto &equation : new_equations) {
        // Process inputs
        int const_zeroes_count = 0;
        for (int input_i = 0; input_i < input_size; input_i++) {
          if (input_chars[input_i] == '?')
            continue;

          uint32_t ids[] = {input_words[input_i].ids_f[bit_pos],
                            input_words[input_i].ids_g[bit_pos],
                            input_words[input_i].char_ids[bit_pos]};
          if (ids[0] == state.zero_var_id) {
            const_zeroes_count++;
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
        equations.push_back (equation);
      }
    }
  }
}

int load_1bit_two_bit_rules (ifstream &db,
                             cache::lru_cache<string, string> &cache);
} // namespace SHA256

#endif