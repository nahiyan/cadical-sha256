#ifndef _sha256_1_bit_propagate_hpp_INCLUDED
#define _sha256_1_bit_propagate_hpp_INCLUDED

#include "../lru_cache.hpp"
#include "../propagate.hpp"
#include "../state.hpp"
#include "../util.hpp"
#include <iterator>
#include <list>
#include <string>

using namespace std;

namespace SHA256 {
extern pair<int, int> prop_diff_sizes[10];
extern vector<int> (*prop_functions[10]) (vector<int>);
inline void custom_1bit_propagate (State &state,
                                   vector<int> &propagation_lits,
                                   map<int, Reason> &reasons) {
  for (auto &level : state.prop_markings_trail) {
    for (auto marking_it = level.begin (); marking_it != level.end ();
         marking_it++) {
      auto op_id = marking_it->op_id;
      auto step_i = marking_it->step_i;
      auto bit_pos = marking_it->bit_pos;

      marking_it = level.erase (marking_it);

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
      assert (input_size + output_size == int (all_char_ids.size ()));

      // Propagate
      auto &function = prop_functions[op_id];
      // auto timer = new Timer (&state.temp_time);
      string prop_output =
          otf_propagate (function, input_chars, output_chars);
      // delete timer;
      // printf ("Prop: %s %s -> %s\n", input_chars.c_str (),
      //         output_chars.c_str (), prop_output.c_str ());
      if (output_chars == prop_output)
        continue;

      for (auto &c : input_chars)
        assert (c == '-' || c == 'x' || c == 'u' || c == 'n' || c == '1' ||
                c == '0' || c == '?');

      // Construct the antecedent with inputs
      Reason reason;
      int const_zeroes_count = 0;
      for (long x = 0; x < input_size; x++) {
        if (input_chars[x] == '?')
          continue;

        uint32_t ids[] = {input_words[x].ids_f[bit_pos],
                          input_words[x].ids_g[bit_pos],
                          input_words[x].char_ids[bit_pos]};

        // Count the const zeroes
        if (ids[0] == state.zero_var_id) {
          const_zeroes_count++;
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
        continue;

      // Construct the antecedent with outputs
      vector<int> prop_lits;
      for (long x = 0; x < output_size; x++) {
        // Ignore the high carry output if addends can't add up to >= 4
        if (function == add_ && x == 0 &&
            (input_size - const_zeroes_count) < 4)
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

      // Since we're done with the antecedent, we can insert the reasons
      for (auto &lit : prop_lits)
        reasons[lit] = reason;

      // if (!propagation_lits.empty ())
      //   return;
    }
  }
  // for (int op_id = 9; op_id >= 0; op_id--)
  //   for (int step_i = state.order - 1; step_i >= 0; step_i--)
  //     for (int bit_pos = 31; bit_pos >= 0; bit_pos--) {
  //       auto &marking = state.marked_operations_prop[(OperationId) op_id]
  //                                                   [step_i][bit_pos];
  //       if (!marking)
  //         continue;
  //       marking = false;

  //     }
}
int load_1bit_prop_rules (ifstream &db,
                          cache::lru_cache<string, string> &cache);
} // namespace SHA256

#endif