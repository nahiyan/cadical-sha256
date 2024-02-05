#include "../sha256.hpp"
#include "../state.hpp"
#include "../types.hpp"
#include "../util.hpp"
#include <cassert>

namespace SHA256 {
void get_4bit_differential (OperationId op_id, int step_i, int bit_pos,
                            State &state, vector<Differential> &diffs) {
  struct Operation {
    FunctionId function_id;
    SoftWord *operands;
    vector<Word *> outputs;
    int input_size, output_size;
    string mask;
  };

  auto get_operation = [] (OperationId id, int step_i, State &state) {
    auto &ops = state.operations[step_i];
    auto &step = state.steps[step_i];
    switch (id) {
    case op_s0:
      assert (step_i >= 16);
      return Operation{xor3, ops.s0.inputs, {&step.s0}, 3, 1, "+++."};
    case op_s1:
      assert (step_i >= 16);
      return Operation{xor3, ops.s1.inputs, {&step.s1}, 3, 1, "+++."};
    case op_sigma0:
      return Operation{xor3,  ops.sigma0.inputs, {&step.sigma0}, 3, 1,
                       "+++."};
    case op_sigma1:
      return Operation{xor3,  ops.sigma1.inputs, {&step.sigma1}, 3, 1,
                       "+++."};
    case op_maj:
      return Operation{maj, ops.maj.inputs, {&step.maj}, 3, 1, "+++."};
    case op_ch:
      return Operation{ch, ops.ch.inputs, {&step.ch}, 3, 1, "+++."};
    case op_add_w:
      assert (step_i >= 16);
      return Operation{add,
                       ops.add_w.inputs,
                       {&step.add_w_r[1], &step.add_w_r[0], &step.w},
                       6,
                       3,
                       ".+.+....+"};
    case op_add_a:
      return Operation{add,
                       ops.add_a.inputs,
                       {&step.add_a_r[1], &step.add_a_r[0],
                        &state.steps[ABS_STEP (step_i)].a},
                       5,
                       3,
                       "+......+"};
    case op_add_e:
      return Operation{add,
                       ops.add_e.inputs,
                       {&state.zero_word, &step.add_e_r[0],
                        &state.steps[ABS_STEP (step_i)].e},
                       3,
                       3,
                       "++...+"};
    case op_add_t:
      return Operation{add,
                       ops.add_t.inputs,
                       {&step.add_t_r[1], &step.add_t_r[0], &step.t},
                       7,
                       3,
                       "+...+....+"};
    default:
      // This condition shouldn't be met
      assert (false);
      return Operation{};
    }
  };

  auto operation = get_operation (op_id, step_i, state);
  FunctionId &function_id = operation.function_id;
  SoftWord *input_words = operation.operands;
  vector<Word *> output_words = operation.outputs;
  int input_size = operation.input_size,
      output_size = operation.output_size;
  auto function = function_id == maj    ? maj_
                  : function_id == ch   ? ch_
                  : function_id == xor3 ? xor_
                                        : add_;
  auto &i = step_i;
  auto &j = bit_pos;

  Differential diff;
  diff.function = function;
  diff.operation_id = op_id;
  diff.step_index = i;
  diff.bit_pos = j;
  diff.mask = operation.mask;

  for (int x = 0; x < input_size; x++) {
    auto &input_word = input_words[x];
    assert (input_word.chars[j] != NULL);
    diff.inputs += *(input_word.chars[j]);
    diff.char_base_ids.first.push_back (input_word.char_ids[j]);

    diff.table_values.first.push_back (
        gc_values_4bit (*input_word.chars[j]));
    assert (diff.table_values.first[x] != 0);
  }
  assert (int (diff.inputs.size ()) == input_size);
  assert (int (diff.char_base_ids.first.size ()) == input_size);
  assert (int (diff.table_values.first.size ()) == input_size);

  for (int x = 0; x < output_size; x++) {
    auto &output_word = output_words[x];
    diff.outputs += output_word->chars[j];
    diff.char_base_ids.second.push_back (output_word->char_ids[j]);

    diff.table_values.second.push_back (
        gc_values_4bit (output_word->chars[j]));
    assert (diff.table_values.second[x] != 0);
  }
  assert (int (diff.outputs.size ()) == output_size);
  assert (int (diff.char_base_ids.second.size ()) == output_size);
  assert (int (diff.table_values.second.size ()) == output_size);

  diffs.push_back (diff);
}
} // namespace SHA256