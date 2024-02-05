#include "state.hpp"
#include "1_bit/state.hpp"
#include "4_bit/state.hpp"
#include "sha256.hpp"
#include "util.hpp"

using namespace SHA256;

void State::refresh_char (Word &word, int index) {
  auto &id_f = word.ids_f[index];
  auto &id_g = word.ids_g[index];
  auto &base_id = word.char_ids[index];
  char &c = word.chars[index];
  char c_before = c;

  if (id_f == 0 || id_g == 0 || base_id == 0) {
    c = '?';
    return;
  }
  assert (word.chars.size () == 32);

#if IS_4BIT
  uint8_t diff[] = {partial_assignment.get (base_id + 0),
                    partial_assignment.get (base_id + 1),
                    partial_assignment.get (base_id + 2),
                    partial_assignment.get (base_id + 3)};
  refresh_4bit_char (diff, c);
#else
  uint8_t x = partial_assignment.get (id_f);
  uint8_t x_ = partial_assignment.get (id_g);
  uint8_t diff = partial_assignment.get (base_id);
  refresh_1bit_char (x, x_, diff, c);
#endif

  char c_after = c;
  if (c_before == c_after)
    return;

  // Mark the operation if the new char has a higher score
  if (c_before == '?' || compare_gcs (c_before, c_after)) {
    auto &operations = vars_info[base_id].operations;
    for (auto &operation : operations) {
      auto &op_id = get<0> (operation);
      auto &step = get<1> (operation);
      auto &pos = get<2> (operation);
      marked_operations[op_id][step][pos] = true;
      last_marked_op = {op_id, step, pos};
    }
  }
}

void State::soft_refresh () {
  for (auto &base_id : partial_assignment.updated_vars) {
    auto &info = vars_info[base_id];
    refresh_char (*info.word, 31 - info.identity.col);
  }
  partial_assignment.updated_vars.clear ();
}

void State::refresh_word (Word &word) {
  for (int col = 0; col < 32; col++)
    refresh_char (word, col);
}

void State::hard_refresh (bool will_propagate) {
  auto get_soft_word_chars = [] (SoftWord &soft_word) {
    string chars;
    for (int i = 0; i < 32; i++)
      chars += *soft_word.chars[i];
    return chars;
  };

  for (int i = -4; i < order; i++) {
    // step < 0
    auto &step = steps[ABS_STEP (i)];
    refresh_word (step.a);
    refresh_word (step.e);

    if (i >= 0) {
      auto &step = steps[i];
      refresh_word (step.w);
      refresh_word (step.sigma0);
      refresh_word (step.sigma1);
      refresh_word (step.ch);
      refresh_word (step.maj);
      refresh_word (step.k);
      refresh_word (step.t);
      refresh_word (step.add_t_r[0]);
      refresh_word (step.add_t_r[1]);
      refresh_word (step.add_e_r[0]);
      refresh_word (step.add_a_r[0]);
      refresh_word (step.add_a_r[1]);

      if (i >= 16) {
        refresh_word (step.s0);
        refresh_word (step.s1);
        refresh_word (step.add_w_r[0]);
        refresh_word (step.add_w_r[1]);

        // if (will_propagate) {
        //   {
        //     // s0
        //     vector<string> inputs (3);
        //     for (int j = 0; j < 3; j++)
        //       inputs[j] = get_soft_word_chars
        //       (operations[i].s0.inputs[j]);

        //     step.s0.chars = propagate (xor3, inputs, step.s0.chars);
        //   }
        //   {
        //     // s1
        //     vector<string> inputs (3);
        //     for (int j = 0; j < 3; j++)
        //       inputs[j] = get_soft_word_chars
        //       (operations[i].s1.inputs[j]);
        //     step.s1.chars = propagate (xor3, inputs, step.s1.chars);
        //   }

        //   prop_with_int_diff (add_w, {
        //                                  &steps[i].w.chars,
        //                                  &steps[i].s1.chars,
        //                                  &steps[i - 7].w.chars,
        //                                  &steps[i].s0.chars,
        //                                  &steps[i - 16].w.chars,
        //                              });
        // }
      }

      // if (will_propagate) {
      //   {
      //     // sigma0
      //     vector<string> inputs (3);
      //     for (int j = 0; j < 3; j++)
      //       inputs[j] =
      //           get_soft_word_chars (operations[i].sigma0.inputs[j]);
      //     step.sigma0.chars = propagate (xor3, inputs,
      //     step.sigma0.chars);
      //   }
      //   {
      //     // sigma1
      //     vector<string> inputs (3);
      //     for (int j = 0; j < 3; j++)
      //       inputs[j] =
      //           get_soft_word_chars (operations[i].sigma1.inputs[j]);
      //     step.sigma1.chars = propagate (xor3, inputs,
      //     step.sigma1.chars);
      //   }

      //   {
      //     // maj
      //     vector<string> inputs (3);
      //     for (int j = 0; j < 3; j++)
      //       inputs[j] = get_soft_word_chars
      //       (operations[i].maj.inputs[j]);
      //     step.maj.chars = propagate (maj, inputs, step.maj.chars);
      //   }
      //   {
      //     // ch
      //     vector<string> inputs (3);
      //     for (int j = 0; j < 3; j++)
      //       inputs[j] = get_soft_word_chars (operations[i].ch.inputs[j]);
      //     step.ch.chars = propagate (ch, inputs, step.ch.chars);
      //   }

      //   prop_with_int_diff (add_e, {
      //                                  &steps[ABS_STEP (i)].e.chars,
      //                                  &steps[ABS_STEP (i - 4)].a.chars,
      //                                  &steps[ABS_STEP (i - 4)].e.chars,
      //                                  &steps[i].sigma1.chars,
      //                                  &steps[i].ch.chars,
      //                                  &steps[i].w.chars,
      //                              });
      //   prop_with_int_diff (add_a, {
      //                                  &steps[ABS_STEP (i)].a.chars,
      //                                  &steps[ABS_STEP (i)].e.chars,
      //                                  &steps[ABS_STEP (i - 4)].a.chars,
      //                                  &steps[i].sigma0.chars,
      //                                  &steps[i].maj.chars,
      //                              });
      // }
    }
  }
}

void State::print () {
  for (int i = -4; i < order; i++) {
    auto &step = steps[ABS_STEP (i)];
    printf (i >= 0 && i <= 9 ? " %d " : "%d ", i);
    printf ("%s %s", step.a.chars.c_str (), step.e.chars.c_str ());
    if (i >= 0) {
      auto &step_ = steps[i];
      printf (" %s", step_.w.chars.c_str ());
      if (i >= 16) {
        printf (" %s", step_.s0.chars.c_str ());
        printf (" %s", step_.s1.chars.c_str ());
      } else {
        printf ("                                 ");
        printf ("                                 ");
      }
      printf (" %s", step_.sigma0.chars.c_str ());
      printf (" %s", step_.sigma1.chars.c_str ());
      printf (" %s", step_.maj.chars.c_str ());
      printf (" %s", step_.ch.chars.c_str ());
    }
    printf ("\n");
  }
}