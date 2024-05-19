#include "sha256.hpp"
#include "state.hpp"
#include "types.hpp"
#include "util.hpp"

namespace SHA256 {
#if !IS_LI2024
void State::set_operations () {
  // TODO: Free up this heap allocation later
  char *zero_char = new char;
  *zero_char = '0';

  auto to_vec = [] (uint32_t *ids) {
    vector<uint32_t> vec (32);
    for (int i = 0; i < 32; i++)
      vec[i] = ids[i];
    return vec;
  };

  auto to_soft_word = [this, zero_char] (Word &word, int shift = 0) {
    SoftWord soft_word;
    for (int i = 0; i < 32; i++) {
      int shifted_pos = i + shift;
      if (shifted_pos >= 0 && shifted_pos <= 31) {
        soft_word.ids_f[i] = word.ids_f[shifted_pos];
        soft_word.ids_g[i] = word.ids_g[shifted_pos];
        soft_word.char_ids[i] = word.char_ids[shifted_pos];
        soft_word.chars[i] = &word.chars[shifted_pos];
      } else {
        soft_word.ids_f[i] = zero_var_id;
        soft_word.ids_g[i] = zero_var_id + 1;
        soft_word.char_ids[i] = zero_var_id + 2;
        soft_word.chars[i] = zero_char;
      }
    }
    return soft_word;
  };

  auto add_var_info_sword = [this] (SoftWord *word, int step,
                                    OperationId op_id) {
    for (int pos = 0; pos < 32; pos++) {
      this->vars_info[word->ids_f[pos]].operations.push_back (
          {op_id, step, pos});
      this->vars_info[word->ids_g[pos]].operations.push_back (
          {op_id, step, pos});
      int k = 0;
#if ENC_TYPE == FourBit
      for (; k < 4; k++)
#endif
        this->vars_info[word->char_ids[pos] + k].operations.push_back (
            {op_id, step, pos});
    }
  };

  auto add_var_info_word = [this] (Word *word, int step,
                                   OperationId op_id) {
    for (int pos = 0; pos < 32; pos++) {
      this->vars_info[word->ids_f[pos]].operations.push_back (
          {op_id, step, pos});
      this->vars_info[word->ids_g[pos]].operations.push_back (
          {op_id, step, pos});
      int k = 0;
#if ENC_TYPE == FourBit
      for (; k < 4; k++)
#endif
        this->vars_info[word->char_ids[pos] + k].operations.push_back (
            {op_id, step, pos});
    }
  };

  // Set updated operations array
  for (int i = 0; i < 10; i++)
    for (int j = 0; j < 64; j++)
      marked_operations_strong_prop[i][j] = false;

  // Zero word
  for (int i = 0; i < 32; i++) {
    zero_word.chars[i] = '0';
    zero_word.ids_f[i] = zero_var_id;
    zero_word.ids_g[i] = zero_var_id + 1;
    zero_word.char_ids[i] = zero_var_id + 2;
  }

  for (int i = 0; i < order; i++) {
    if (i >= 16) {
      {
        // s0
        Word &word = steps[i - 15].w;
        SoftWord *operands = operations[i].s0.inputs;

        vector<int> indices[3];
        for (int j = 0; j < 32; j++)
          for (int k = 0; k < 3; k++)
            indices[k].push_back (31 - j);
        indices[0] = rotate_vec (indices[0], 7);
        indices[1] = rotate_vec (indices[1], 18);
        indices[2] = rotate_vec (indices[2], 3, false);

        for (int k = 0; k < 3; k++)
          for (int j = 0; j < 32; j++) {
            operands[k].ids_f[31 - j] = k == 2 && j < 3
                                            ? zero_var_id + 0
                                            : word.ids_f[indices[k][j]];
            operands[k].ids_g[31 - j] = k == 2 && j < 3
                                            ? zero_var_id + 1
                                            : word.ids_g[indices[k][j]];
            operands[k].char_ids[31 - j] =
                k == 2 && j < 3 ? zero_var_id + 2
                                : word.char_ids[indices[k][j]];
            operands[k].chars[31 - j] =
                k == 2 && j < 3 ? zero_char : &word.chars[indices[k][j]];
          }

        for (int j = 0; j < 3; j++)
          add_var_info_sword (&operands[j], i, op_s0);
        add_var_info_word (&steps[i].s0, i, op_s0);

        // Set the outputs
        operations[i].s0.outputs[0] = &steps[i].s0;

        operations[i].inputs_by_op_id[op_s0] = operations[i].s0.inputs;
        operations[i].outputs_by_op_id[op_s0] = operations[i].s0.outputs;
      }
      {
        // s1
        Word &word = steps[i - 2].w;
        SoftWord *operands = operations[i].s1.inputs;

        vector<int> indices[3];
        for (int j = 0; j < 32; j++)
          for (int k = 0; k < 3; k++)
            indices[k].push_back (31 - j);
        indices[0] = rotate_vec (indices[0], 17);
        indices[1] = rotate_vec (indices[1], 19);
        indices[2] = rotate_vec (indices[2], 10, false);

        for (int k = 0; k < 3; k++)
          for (int j = 0; j < 32; j++) {
            operands[k].ids_f[31 - j] = k == 2 && j < 10
                                            ? zero_var_id + 0
                                            : word.ids_f[indices[k][j]];
            operands[k].ids_g[31 - j] = k == 2 && j < 10
                                            ? zero_var_id + 1
                                            : word.ids_g[indices[k][j]];
            operands[k].char_ids[31 - j] =
                k == 2 && j < 10 ? zero_var_id + 2
                                 : word.char_ids[indices[k][j]];
            operands[k].chars[31 - j] =
                k == 2 && j < 10 ? zero_char : &word.chars[indices[k][j]];
          }

        for (int j = 0; j < 3; j++)
          add_var_info_sword (&operands[j], i, op_s1);
        add_var_info_word (&steps[i].s1, i, op_s1);

        if (i == 20) {
          assert (vars_info[operands[0].char_ids[22]].identity.col == 7);
          assert (
              get<2> (vars_info[operands[0].char_ids[22]].operations[0]) ==
              7);
        }

        // Set the outputs
        operations[i].s1.outputs[0] = &steps[i].s1;

        operations[i].inputs_by_op_id[op_s1] = operations[i].s1.inputs;
        operations[i].outputs_by_op_id[op_s1] = operations[i].s1.outputs;
      }
      {
        // add.W
        Word *words[] = {&steps[i].s1, &steps[i - 7].w, &steps[i].s0,
                         &steps[i - 16].w};
        auto &operands = operations[i].add_w.inputs;
        for (int j = 0; j < 4; j++)
          operands[j] = to_soft_word (*words[j]);
        operands[4] = to_soft_word (steps[i].add_w_r[0], -1);
        operands[5] = to_soft_word (steps[i].add_w_r[1], -2);

        for (int j = 0; j < 6; j++)
          add_var_info_sword (&operands[j], i, op_add_w);
        add_var_info_word (&steps[i].w, i, op_add_w);

        // Set the outputs
        operations[i].add_w.outputs[0] = &steps[i].add_w_r[1];
        operations[i].add_w.outputs[1] = &steps[i].add_w_r[0];
        operations[i].add_w.outputs[2] = &steps[i].w;

        operations[i].inputs_by_op_id[op_add_w] =
            operations[i].add_w.inputs;
        operations[i].outputs_by_op_id[op_add_w] =
            operations[i].add_w.outputs;
      }
    }

    {
      // sigma0
      Word &word = steps[ABS_STEP (i - 1)].a;
      SoftWord *operands = operations[i].sigma0.inputs;

      vector<int> indices[3];
      for (int j = 0; j < 32; j++)
        for (int k = 0; k < 3; k++)
          indices[k].push_back (31 - j);
      indices[0] = rotate_vec (indices[0], 2);
      indices[1] = rotate_vec (indices[1], 13);
      indices[2] = rotate_vec (indices[2], 22);

      for (int k = 0; k < 3; k++)
        for (int j = 0; j < 32; j++) {
          operands[k].ids_f[31 - j] = word.ids_f[indices[k][j]];
          operands[k].ids_g[31 - j] = word.ids_g[indices[k][j]];
          operands[k].char_ids[31 - j] = word.char_ids[indices[k][j]];
          operands[k].chars[31 - j] = &word.chars[indices[k][j]];
        }

      for (int j = 0; j < 3; j++)
        add_var_info_sword (&operands[j], i, op_sigma0);
      add_var_info_word (&steps[i].sigma0, i, op_sigma0);

      // Set the outputs
      operations[i].sigma0.outputs[0] = &steps[i].sigma0;

      operations[i].inputs_by_op_id[op_sigma0] =
          operations[i].sigma0.inputs;
      operations[i].outputs_by_op_id[op_sigma0] =
          operations[i].sigma0.outputs;
    }
    {
      // sigma1
      Word &word = steps[ABS_STEP (i - 1)].e;
      SoftWord *operands = operations[i].sigma1.inputs;

      vector<int> indices[3];
      for (int j = 0; j < 32; j++)
        for (int k = 0; k < 3; k++)
          indices[k].push_back (31 - j);
      indices[0] = rotate_vec (indices[0], 6);
      indices[1] = rotate_vec (indices[1], 11);
      indices[2] = rotate_vec (indices[2], 25);

      for (int k = 0; k < 3; k++)
        for (int j = 0; j < 32; j++) {
          operands[k].ids_f[31 - j] = word.ids_f[indices[k][j]];
          operands[k].ids_g[31 - j] = word.ids_g[indices[k][j]];
          operands[k].char_ids[31 - j] = word.char_ids[indices[k][j]];
          operands[k].chars[31 - j] = &word.chars[indices[k][j]];
        }

      for (int j = 0; j < 3; j++)
        add_var_info_sword (&operands[j], i, op_sigma1);
      add_var_info_word (&steps[i].sigma1, i, op_sigma1);

      // Set the outputs
      operations[i].sigma1.outputs[0] = &steps[i].sigma1;

      operations[i].inputs_by_op_id[op_sigma1] =
          operations[i].sigma1.inputs;
      operations[i].outputs_by_op_id[op_sigma1] =
          operations[i].sigma1.outputs;
    }
    {
      // maj
      auto &operands = operations[i].maj.inputs;
      for (int j = 1; j <= 3; j++)
        operands[j - 1] = to_soft_word (steps[ABS_STEP (i - j)].a);

      for (int j = 0; j < 3; j++)
        add_var_info_sword (&operands[j], i, op_maj);
      add_var_info_word (&steps[i].maj, i, op_maj);

      // Set the outputs
      operations[i].maj.outputs[0] = &steps[i].maj;

      operations[i].inputs_by_op_id[op_maj] = operations[i].maj.inputs;
      operations[i].outputs_by_op_id[op_maj] = operations[i].maj.outputs;
    }
    {
      // ch
      auto &operands = operations[i].ch.inputs;
      for (int j = 1; j <= 3; j++)
        operands[j - 1] = to_soft_word (steps[ABS_STEP (i - j)].e);

      for (int j = 0; j < 3; j++)
        add_var_info_sword (&operands[j], i, op_ch);
      add_var_info_word (&steps[i].ch, i, op_ch);

      // Set the outputs
      operations[i].ch.outputs[0] = &steps[i].ch;

      operations[i].inputs_by_op_id[op_ch] = operations[i].ch.inputs;
      operations[i].outputs_by_op_id[op_ch] = operations[i].ch.outputs;
    }
    {
      // add.T
      Word *words[] = {
          &steps[ABS_STEP (i - 4)].e,
          &steps[i].sigma1,
          &steps[i].ch,
          &steps[i].k,
          &steps[i].w,
      };
      auto &operands = operations[i].add_t.inputs;
      for (int j = 0; j < 5; j++)
        operands[j] = to_soft_word (*words[j]);
      operands[5] = to_soft_word (steps[i].add_t_r[0], -1);
      operands[6] = to_soft_word (steps[i].add_t_r[1], -2);

      assert (operands[6].ids_f[0] == zero_var_id);
      assert (operands[6].ids_f[1] == zero_var_id);
      assert (operands[6].ids_f[2] == steps[i].add_t_r[1].ids_f[0]);
      assert (operands[6].ids_f[31] == steps[i].add_t_r[1].ids_f[29]);

      for (int j = 0; j < 7; j++)
        add_var_info_sword (&operands[j], i, op_add_t);
      add_var_info_word (&steps[i].t, i, op_add_t);

      // Set the outputs
      operations[i].add_t.outputs[0] = &steps[i].add_t_r[1];
      operations[i].add_t.outputs[1] = &steps[i].add_t_r[0];
      operations[i].add_t.outputs[2] = &steps[i].t;

      operations[i].inputs_by_op_id[op_add_t] = operations[i].add_t.inputs;
      operations[i].outputs_by_op_id[op_add_t] =
          operations[i].add_t.outputs;
    }
    {
      // add.E
      auto &operands = operations[i].add_e.inputs;
      Word *words[] = {
          &steps[ABS_STEP (i - 4)].a,
          &steps[i].t,
      };
      for (int j = 0; j < 2; j++)
        operands[j] = to_soft_word (*words[j]);
      operands[2] = to_soft_word (steps[i].add_e_r[0], -1);

      assert (operands[2].ids_f[0] == zero_var_id);
      assert (operands[2].ids_f[1] == steps[i].add_e_r[0].ids_f[0]);
      assert (operands[2].ids_f[31] == steps[i].add_e_r[0].ids_f[30]);

      for (int j = 0; j < 3; j++)
        add_var_info_sword (&operands[j], i, op_add_e);
      add_var_info_word (&steps[ABS_STEP (i)].e, i, op_add_e);

      // Set the outputs
      operations[i].add_e.outputs[0] = &zero_word;
      operations[i].add_e.outputs[1] = &steps[i].add_e_r[0];
      operations[i].add_e.outputs[2] = &steps[ABS_STEP (i)].e;

      operations[i].inputs_by_op_id[op_add_e] = operations[i].add_e.inputs;
      operations[i].outputs_by_op_id[op_add_e] =
          operations[i].add_e.outputs;
    }
    {
      // add.A
      auto &operands = operations[i].add_a.inputs;
      Word *words[] = {&steps[i].t, &steps[i].sigma0, &steps[i].maj};
      for (int j = 0; j < 3; j++)
        operands[j] = to_soft_word (*words[j]);
      operands[3] = to_soft_word (steps[i].add_a_r[0], -1);
      operands[4] = to_soft_word (steps[i].add_a_r[1], -2);

      assert (operands[4].ids_f[0] == zero_var_id);
      assert (operands[4].ids_f[1] == zero_var_id);
      assert (operands[4].ids_f[2] != zero_var_id);
      assert (operands[3].ids_f[0] == zero_var_id);
      assert (operands[3].ids_f[1] != zero_var_id);
      assert (operands[4].ids_f[2] == steps[i].add_a_r[1].ids_f[0]);
      assert (operands[4].ids_f[31] == steps[i].add_a_r[1].ids_f[29]);
      assert (operands[3].ids_f[2] == steps[i].add_a_r[0].ids_f[1]);
      assert (operands[3].ids_f[31] == steps[i].add_a_r[0].ids_f[30]);

      for (int j = 0; j < 5; j++)
        add_var_info_sword (&operands[j], i, op_add_a);
      add_var_info_word (&steps[ABS_STEP (i)].a, i, op_add_a);

      // Set the outputs
      operations[i].add_a.outputs[0] = &steps[i].add_a_r[1];
      operations[i].add_a.outputs[1] = &steps[i].add_a_r[0];
      operations[i].add_a.outputs[2] = &steps[ABS_STEP (i)].a;

      operations[i].inputs_by_op_id[op_add_a] = operations[i].add_a.inputs;
      operations[i].outputs_by_op_id[op_add_a] =
          operations[i].add_a.outputs;
    }
  }
}

void State::print_operations () {
  auto print_chars_sword = [] (SoftWord &word) {
    for (int i = 31; i >= 0; i--)
      printf ("%c", *word.chars[i]);
  };
  auto print_chars_word = [] (Word &word) {
    for (int i = 31; i >= 0; i--)
      printf ("%c", word.chars[i]);
  };

  for (int i = 16; i < order; i++) {
    // add.W
    {
      printf ("\nW_%d = s1(W_%d) + W_%d + s0(W_%d) + W_%d\n", i, i - 2,
              i - 7, i - 15, i - 16);
      auto &inputs = operations[i].add_w.inputs;
      auto &outputs = operations[i].add_w.outputs;
      for (int k = 0; k < 6; k++) {
        print_chars_sword (inputs[k]);
        printf ("\n");
      }
      printf ("\n");
      for (int k = 0; k < 3; k++) {
        print_chars_word (*outputs[k]);
        printf ("\n");
      }
    }
  }

  for (int i = 0; i < order; i++) {
    // add.A
    {
      printf ("\nA_%d = T_%d + sigma0(A_%d) + MAJ(A_%d, A_%d, A_%d)\n", i,
              i, i - 1, i - 1, i - 2, i - 3);
      auto &inputs = operations[i].add_a.inputs;
      auto &outputs = operations[i].add_a.outputs;

      for (int k = 0; k < 5; k++) {
        print_chars_sword (inputs[k]);
        printf ("\n");
      }
      printf ("\n");
      for (int k = 0; k < 3; k++) {
        print_chars_word (*outputs[k]);
        printf ("\n");
      }
    }
  }

  for (int i = 0; i < order; i++) {
    // add.E
    {
      printf ("\nE_%d = A_%d + T_%d\n", i, i - 4, i);
      auto &inputs = operations[i].add_e.inputs;
      auto &outputs = operations[i].add_e.outputs;

      for (int k = 0; k < 3; k++) {
        print_chars_sword (inputs[k]);
        printf ("\n");
      }
      printf ("\n");
      for (int k = 0; k < 3; k++) {
        print_chars_word (*outputs[k]);
        printf ("\n");
      }
    }
  }

  for (int i = 0; i < order; i++) {
    // add.T
    {
      printf ("\nT_%d = E_%d + sigma1(E_%d) + IF(E_%d, E_%d, E_%d) + K_%d "
              "+ W_%d\n",
              i, i - 4, i - 1, i - 1, i - 2, i - 3, i, i);
      auto &inputs = operations[i].add_t.inputs;
      auto &outputs = operations[i].add_t.outputs;

      for (int k = 0; k < 7; k++) {
        print_chars_sword (inputs[k]);
        printf ("\n");
      }
      printf ("\n");
      for (int k = 0; k < 3; k++) {
        print_chars_word (*outputs[k]);
        printf ("\n");
      }
    }
  }

  // TODO: Print the rest of the operations
}
#endif
} // namespace SHA256