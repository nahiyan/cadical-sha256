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
                                   list<int> &propagation_lits,
                                   map<int, Reason> &reasons,
                                   Stats &stats) {
  assert (propagation_lits.empty ());
  for (auto level = state.prop_markings_trail.end ();
       level-- != state.prop_markings_trail.begin ();) {
    for (auto marking_it = level->end ();
         marking_it-- != level->begin ();) {
      auto op_id = marking_it->op_id;
      auto step_i = marking_it->step_i;
      auto bit_index = 31 - marking_it->bit_pos;

      marking_it = level->erase (marking_it);

      // Construct the differential
      int input_size = prop_diff_sizes[op_id].first,
          output_size = prop_diff_sizes[op_id].second;
      auto &input_words = state.operations[step_i].inputs_by_op_id[op_id];
      auto &output_words = state.operations[step_i].outputs_by_op_id[op_id];
      string input_chars, output_chars;
      for (int i = 0; i < input_size; i++)
        input_chars += *input_words[i].chars[bit_index];
      for (int i = 0; i < output_size; i++)
        output_chars += output_words[i]->chars[bit_index];
      auto &function = prop_functions[op_id];

      // Skip differentials with low probability
      if (function != add_) {
        int q_count = 0;
        for (auto &c : input_chars)
          if (c == '?')
            q_count++;
        for (auto &c : output_chars)
          if (c == '?')
            q_count++;

        if (q_count == 0 || q_count == input_size + output_size)
          continue;
      }

      // Propagate
      // Timer *timer = new Timer (&stats.total_prop_time);
      auto output =
          otf_propagate (function, input_chars, output_chars, &stats);
      // delete timer;
      string &prop_input = output.first;
      string &prop_output = output.second;
      // printf ("Prop: %s %s -> %s\n", input_chars.c_str (),
      //         output_chars.c_str (), prop_output.c_str ());
      if (output_chars == prop_output && input_chars == prop_input) {
        // printf ("Useless prop: %s -> %s\n", input_chars.c_str (),
        //         output_chars.c_str ());
        continue;
      }
      // printf ("Useful prop: %s -> %s to %s -> %s\n", input_chars.c_str
      // (),
      //         output_chars.c_str (), prop_input.c_str (),
      //         prop_output.c_str ());

      for (auto &c : input_chars)
        assert (c == '-' || c == 'x' || c == 'u' || c == 'n' || c == '1' ||
                c == '0' || c == '?');

      // Construct the antecedent with inputs
      Reason reason;
      int const_zeroes_count = 0;
      for (long x = 0; x < input_size; x++) {
        if (input_chars[x] == '?')
          continue;

        uint32_t ids[] = {input_words[x].ids_f[bit_index],
                          input_words[x].ids_g[bit_index],
                          input_words[x].char_ids[bit_index]};

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

        if (prop_input[x] == '#')
          continue;

        auto prop_table_values = gc_values_1bit (prop_input[x]);
        for (int y = 2; y >= 0; y--) {
          auto &id = ids[y];
          if (prop_table_values[y] == 0)
            continue;
          int lit = prop_table_values[y] * id;
          if (lit == 0)
            continue;

          if (state.partial_assignment.get (id) != LIT_UNDEF)
            continue;

          // We're pushing to the front because we move down the trail
          propagation_lits.push_back (lit);
        }
      }

      if (reason.antecedent.empty ())
        continue;

      // Construct the antecedent with outputs
      for (long x = 0; x < output_size; x++) {
        // Ignore the high carry output if addends can't add up to >= 4
        if (function == add_ && x == 0 &&
            (input_size - const_zeroes_count) < 4)
          continue;

        uint32_t ids[] = {output_words[x]->ids_f[bit_index],
                          output_words[x]->ids_g[bit_index],
                          output_words[x]->char_ids[bit_index]};

        if (ids[0] == state.zero_var_id)
          continue;

        auto table_values = gc_values_1bit (output_chars[x]);
        bool has_output_antecedent = false;
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
        assert (output_chars[x] != '?' ? has_output_antecedent : true);

        if (prop_output[x] == '#')
          continue;

        auto prop_table_values = gc_values_1bit (prop_output[x]);
        for (int y = 2; y >= 0; y--) {
          auto &id = ids[y];
          if (prop_table_values[y] == 0)
            continue;
          int lit = prop_table_values[y] * id;
          if (lit == 0)
            continue;

          if (state.partial_assignment.get (id) != LIT_UNDEF)
            continue;

          propagation_lits.push_back (lit);
        }
      }

      // Since we're done with the antecedent, we can insert the reasons
      for (auto &lit : propagation_lits)
        reasons[lit] = reason;

      if (!propagation_lits.empty ())
        return;
    }
  }
}
int load_1bit_prop_rules (ifstream &db,
                          cache::lru_cache<string, string> &cache);
} // namespace SHA256

#endif