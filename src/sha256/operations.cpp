#include "sha256.hpp"
#include "state.hpp"
#include "types.hpp"
#include "util.hpp"

namespace SHA256 {
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
      if (word->ids_f[pos] == this->zero_var_id)
        continue;

      this->vars_info[word->ids_f[pos]].operations.push_back (
          {op_id, step, 31 - pos});
      this->vars_info[word->ids_g[pos]].operations.push_back (
          {op_id, step, 31 - pos});
      for (int k = 0; k < 4; k++)
        this->vars_info[word->char_ids[pos] + k].operations.push_back (
            {op_id, step, 31 - pos});
    }
  };

  auto add_var_info_word = [this] (Word *word, int step,
                                   OperationId op_id) {
    for (int pos = 0; pos < 32; pos++) {
      if (word->ids_f[pos] == this->zero_var_id)
        continue;

      this->vars_info[word->ids_f[pos]].operations.push_back (
          {op_id, step, 31 - pos});
      this->vars_info[word->ids_g[pos]].operations.push_back (
          {op_id, step, 31 - pos});
      for (int k = 0; k < 4; k++)
        this->vars_info[word->char_ids[pos] + k].operations.push_back (
            {op_id, step, 31 - pos});
    }
  };

  // Set updated operations array
  for (int i = 0; i < 10; i++)
    for (int j = 0; j < 64; j++)
      for (int k = 0; k < 32; k++)
        marked_operations[i][j][k] = false;

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
        vector<uint32_t> id_vecs[] = {to_vec (word.ids_f),
                                      to_vec (word.ids_g),
                                      to_vec (word.char_ids)};
        for (int k = 0; k < 3; k++) {
          vector<uint32_t> inputs[] = {
              rotate_word (id_vecs[k], -7),
              rotate_word (id_vecs[k], -18),
              rotate_word (id_vecs[k], -3, false),
          };
          for (int j = 0; j < 3; j++)
            copy (inputs[j].begin (), inputs[j].end (),
                  k == 0   ? operands[j].ids_f
                  : k == 1 ? operands[j].ids_g
                           : operands[j].char_ids);
        }

        for (int j = 0; j < 32; j++) {
          if (operands[2].ids_f[j] == 0)
            operands[2].ids_f[j] = zero_var_id;
          if (operands[2].ids_g[j] == 0)
            operands[2].ids_g[j] = zero_var_id + 1;
          if (operands[2].char_ids[j] == 0)
            operands[2].char_ids[j] = zero_var_id + 2;
        }

        for (int j = 0; j < 32; j++) {
          operands[0].chars[j] = &word.chars[e_mod (j - 7, 32)];
          operands[1].chars[j] = &word.chars[e_mod (j - 18, 32)];
          // Ensure that the first 3 chars aren't used
          operands[2].chars[j] =
              j >= 3 ? &word.chars[e_mod (j - 3, 32)] : zero_char;
          assert (operands[0].chars[j] != NULL);
          assert (operands[1].chars[j] != NULL);
          assert (operands[2].chars[j] != NULL);
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
        vector<uint32_t> id_vecs[] = {to_vec (word.ids_f),
                                      to_vec (word.ids_g),
                                      to_vec (word.char_ids)};
        for (int k = 0; k < 3; k++) {
          vector<uint32_t> inputs[] = {
              rotate_word (id_vecs[k], -17),
              rotate_word (id_vecs[k], -19),
              rotate_word (id_vecs[k], -10, false),
          };
          for (int j = 0; j < 3; j++)
            copy (inputs[j].begin (), inputs[j].end (),
                  k == 0   ? operands[j].ids_f
                  : k == 1 ? operands[j].ids_g
                           : operands[j].char_ids);
        }

        for (int j = 0; j < 32; j++) {
          if (operands[2].ids_f[j] == 0)
            operands[2].ids_f[j] = zero_var_id;
          if (operands[2].ids_g[j] == 0)
            operands[2].ids_g[j] = zero_var_id + 1;
          if (operands[2].char_ids[j] == 0)
            operands[2].char_ids[j] = zero_var_id + 2;
        }

        for (int j = 0; j < 32; j++) {
          operands[0].chars[j] = &word.chars[e_mod (j - 17, 32)];
          operands[1].chars[j] = &word.chars[e_mod (j - 19, 32)];
          // Ensure that the first 10 chars aren't used
          operands[2].chars[j] =
              j >= 10 ? &word.chars[e_mod (j - 10, 32)] : zero_char;
        }

        for (int j = 0; j < 3; j++)
          add_var_info_sword (&operands[j], i, op_s1);
        add_var_info_word (&steps[i].s1, i, op_s1);

        if (i == 20) {
          assert (vars_info[operands[0].char_ids[31 - 22]].identity.col ==
                  7);
          assert (get<2> (vars_info[operands[0].char_ids[31 - 22]]
                              .operations[0]) == 7);
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
        operands[4] = to_soft_word (steps[i].add_w_r[0], 1);
        operands[5] = to_soft_word (steps[i].add_w_r[1], 2);

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
      vector<uint32_t> id_vecs[] = {
          to_vec (word.ids_f), to_vec (word.ids_g), to_vec (word.char_ids)};
      for (int k = 0; k < 3; k++) {
        vector<uint32_t> inputs[] = {
            rotate_word (id_vecs[k], -2),
            rotate_word (id_vecs[k], -13),
            rotate_word (id_vecs[k], -22),
        };
        for (int j = 0; j < 3; j++)
          copy (inputs[j].begin (), inputs[j].end (),
                k == 0   ? operands[j].ids_f
                : k == 1 ? operands[j].ids_g
                         : operands[j].char_ids);
      }

      for (int j = 0; j < 32; j++) {
        operands[0].chars[j] = &word.chars[e_mod (j - 2, 32)];
        operands[1].chars[j] = &word.chars[e_mod (j - 13, 32)];
        operands[2].chars[j] = &word.chars[e_mod (j - 22, 32)];
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
      vector<uint32_t> id_vecs[] = {
          to_vec (word.ids_f), to_vec (word.ids_g), to_vec (word.char_ids)};
      for (int k = 0; k < 3; k++) {
        vector<uint32_t> inputs[] = {
            rotate_word (id_vecs[k], -6),
            rotate_word (id_vecs[k], -11),
            rotate_word (id_vecs[k], -25),
        };
        for (int j = 0; j < 3; j++)
          copy (inputs[j].begin (), inputs[j].end (),
                k == 0   ? operands[j].ids_f
                : k == 1 ? operands[j].ids_g
                         : operands[j].char_ids);
      }

      for (int j = 0; j < 32; j++) {
        operands[0].chars[j] = &word.chars[e_mod (j - 6, 32)];
        operands[1].chars[j] = &word.chars[e_mod (j - 11, 32)];
        operands[2].chars[j] = &word.chars[e_mod (j - 25, 32)];
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
      operands[5] = to_soft_word (steps[i].add_t_r[0], 1);
      operands[6] = to_soft_word (steps[i].add_t_r[1], 2);

      assert (operands[6].ids_f[31] == zero_var_id);
      assert (operands[6].ids_f[30] == zero_var_id);
      assert (operands[6].ids_f[29] == steps[i].add_t_r[1].ids_f[31]);
      assert (operands[6].ids_f[0] == steps[i].add_t_r[1].ids_f[2]);

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
      operands[2] = to_soft_word (steps[i].add_e_r[0], 1);

      assert (operands[2].ids_f[31] == zero_var_id);
      assert (operands[2].ids_f[30] == steps[i].add_e_r[0].ids_f[31]);
      assert (operands[2].ids_f[0] == steps[i].add_e_r[0].ids_f[1]);

      for (int j = 0; j < 3; j++)
        add_var_info_sword (&operands[j], i, op_add_e);
      add_var_info_word (&steps[i].e, i, op_add_e);

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
      operands[3] = to_soft_word (steps[i].add_a_r[0], 1);
      operands[4] = to_soft_word (steps[i].add_a_r[1], 2);

      assert (operands[4].ids_f[31] == zero_var_id);
      assert (operands[4].ids_f[30] == zero_var_id);
      assert (operands[4].ids_f[29] != zero_var_id);
      assert (operands[3].ids_f[31] == zero_var_id);
      assert (operands[3].ids_f[30] != zero_var_id);
      assert (operands[4].ids_f[29] == steps[i].add_a_r[1].ids_f[31]);
      assert (operands[4].ids_f[0] == steps[i].add_a_r[1].ids_f[2]);
      assert (operands[3].ids_f[29] == steps[i].add_a_r[0].ids_f[30]);
      assert (operands[3].ids_f[0] == steps[i].add_a_r[0].ids_f[1]);

      for (int j = 0; j < 5; j++)
        add_var_info_sword (&operands[j], i, op_add_a);
      add_var_info_word (&steps[i].a, i, op_add_a);

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
  auto print_chars = [] (SoftWord &word) {
    for (int i = 0; i < 32; i++)
      printf ("%c", *word.chars[i]);
    printf (" ");
  };

  for (int i = 16; i < order; i++) {
    auto &word = operations[i].s0;
    printf ("s0: ");
    for (int j = 0; j < 3; j++)
      print_chars (word.inputs[j]);
    cout << steps[i].s0.chars;
    printf ("\n");
  }
  for (int i = 16; i < order; i++) {
    auto &word = operations[i].s1;
    printf ("s1: ");
    for (int j = 0; j < 3; j++)
      print_chars (word.inputs[j]);
    cout << steps[i].s1.chars;
    printf ("\n");
  }

  // TODO: Print the rest of the operations
}
} // namespace SHA256