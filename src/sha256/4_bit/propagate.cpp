#include "../propagate.hpp"
#include "../state.hpp"
#include "../types.hpp"
#include "../util.hpp"
#include "differential.hpp"
#include "propagate.hpp"
#include <cassert>

namespace SHA256 {
void custom_4bit_propagate (State &state, vector<int> &propagation_lits,
                            map<int, Reason> &reasons) {
  while (true) {
    auto &step_i = get<1> (state.last_marked_op);
    if (get<1> (state.last_marked_op) == -1)
      return;
    auto &op_id = get<0> (state.last_marked_op);
    auto &bit_pos = get<2> (state.last_marked_op);
    vector<Differential> diffs;
    get_4bit_differential (op_id, step_i, bit_pos, state, diffs);
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
        if (diff.char_base_ids.first[x] == state.zero_var_id + 2) {
          const_zeroes_count++;
          is_const_zero = true;
          continue;
        }

        // Add lits
        auto &base_id = diff.char_base_ids.first[x];
        for (int y = 0; y < 4; y++) {
          if ((diff.table_values.first[x] >> y & 1) == 1)
            continue;
          assert (state.partial_assignment.get (base_id + y) != LIT_UNDEF);
          reason.antecedent.push_back (base_id + y);
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

        if (diff.char_base_ids.second[x] == state.zero_var_id + 2)
          continue;

        auto &table_values = diff.table_values.second[x];
        bool has_output_antecedent = false;
        {
          if (diff.outputs[x] != '?') {
            assert (table_values != 15);
            for (int y = 0; y < 4; y++) {
              auto &base_id = diff.char_base_ids.second[x];
              if ((table_values >> y & 1) == 1)
                continue;
              reason.antecedent.push_back (base_id + y);
              assert (state.partial_assignment.get (base_id + y) !=
                      LIT_UNDEF);
              has_output_antecedent = true;
            }
          }
        }
        assert (diff.outputs[x] != '?' ? has_output_antecedent : true);

        // TODO: Propagated char should have a higher score
        if (prop_output[x] == '?' || prop_output[x] == '#')
          continue;

        auto prop_table_values = gc_values (prop_output[x]);
        for (int y = 0; y < 4; y++) {
          int id = diff.char_base_ids.second[x] + y;

          uint8_t value = prop_table_values >> y & 1;
          if (value == 1)
            continue;

          if (state.partial_assignment.get (id) != LIT_UNDEF)
            continue;

          int sign = value == 1 ? 1 : -1;
          int lit = sign * id;

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
}
} // namespace SHA256