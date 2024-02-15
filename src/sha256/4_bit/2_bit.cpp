#include "2_bit.hpp"
#include "../2_bit.hpp"
#include "../state.hpp"
#include "../types.hpp"
#include "../util.hpp"
#include <cassert>

namespace SHA256 {
void custom_4bit_block (State &state, TwoBit &two_bit) {
  // TODO: Fix it
  // for (int op_id = 0; op_id < 10; op_id++)
  //   for (int step_i = 0; step_i < state.order; step_i++)
  //     for (int bit_pos = 0; bit_pos < 32; bit_pos++) {
  //       auto &marked_op =
  //           state.marked_operations[(OperationId)
  //           op_id][step_i][bit_pos];
  //       if (!marked_op)
  //         continue;
  //       vector<Differential> diffs;
  //       get_4bit_differential ((OperationId) op_id, step_i, bit_pos,
  //       state,
  //                              diffs);
  //       marked_op = false;
  //       if (diffs.empty ())
  //         break;
  //       for (auto &diff : diffs) {
  //         auto char_base_ids = diff.char_base_ids.first;
  //         char_base_ids.insert (char_base_ids.end (),
  //                               diff.char_base_ids.second.begin (),
  //                               diff.char_base_ids.second.end ());
  //         assert (diff.char_base_ids.first.size () +
  //                     diff.char_base_ids.second.size () ==
  //                 char_base_ids.size ());
  //         auto &op_id = diff.operation_id;
  //         auto &step_i = diff.step_index;
  //         auto &pos = diff.bit_pos;

  //         // Replace the equations for this particular spot
  //         auto &op_eqs = two_bit.eqs_by_op[op_id][step_i][pos];
  //         op_eqs.clear ();
  //         auto equations =
  //             otf_2bit_eqs (diff.function, diff.inputs, diff.outputs,
  //                           char_base_ids, diff.mask);
  //         string all_chars = diff.inputs + diff.outputs;
  //         for (auto &equation : equations) {
  //           // Process inputs
  //           int const_zeroes_count = 0;
  //           for (int input_i = 0;
  //                input_i < int (diff.char_base_ids.first.size ());
  //                input_i++) {
  //             if (diff.inputs[input_i] == '?')
  //               continue;

  //             bool is_const_zero = false;
  //             auto &base_id = diff.char_base_ids.first[input_i];
  //             if (base_id == state.zero_var_id + 2) {
  //               const_zeroes_count++;
  //               is_const_zero = true;
  //               continue;
  //             }

  //             uint8_t values = gc_values_4bit (diff.inputs[input_i]);
  //             for (int k = 0; k < 4; k++) {
  //               if ((values >> k & 1) == 1)
  //                 continue;

  //               uint32_t var = base_id + k;
  //               assert (state.partial_assignment.get (var) == LIT_FALSE);
  //               equation.antecedent.push_back (var);
  //             }
  //           }

  //           // Process outputs
  //           for (int output_i = 0;
  //                output_i < int (diff.char_base_ids.second.size ());
  //                output_i++) {
  //             if (diff.outputs[output_i] == '?')
  //               continue;

  //             // Ignore the high carry output if addends can't add up to
  //             >=
  //             // 4
  //             if (diff.function == add_ && output_i == 0 &&
  //                 (diff.inputs.size () - const_zeroes_count) < 4)
  //               continue;

  //             auto &base_id = diff.char_base_ids.second[output_i];
  //             if (base_id == state.zero_var_id + 2)
  //               continue;

  //             uint8_t values = gc_values_4bit (diff.outputs[output_i]);
  //             for (int k = 0; k < 4; k++) {
  //               if ((values >> k & 1) == 1)
  //                 continue;

  //               uint32_t var = base_id + k;
  //               assert (state.partial_assignment.get (var) == LIT_FALSE);
  //               equation.antecedent.push_back (var);
  //             }
  //           }
  //           assert (!equation.antecedent.empty ());
  //           op_eqs.push_back (equation);
  //         }
  //       }
  //     }
}
} // namespace SHA256