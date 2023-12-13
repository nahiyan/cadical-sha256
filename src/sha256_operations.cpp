#include "sha256.hpp"
#include "sha256_state.hpp"
#include "sha256_util.hpp"

namespace SHA256 {
void State::set_operations () {
  auto to_vec = [] (uint32_t *ids) {
    vector<uint32_t> vec (32);
    for (int i = 0; i < 32; i++)
      vec[i] = ids[i];
    return vec;
  };

  // !IMPORTANT: Free up this heap allocation later
  char *zero_char = (char *) malloc (sizeof (char));
  *zero_char = '0';

  auto to_soft_word = [] (Word &word) {
    SoftWord soft_word;
    for (int i = 0; i < 32; i++) {
      soft_word.ids_f[i] = word.ids_f[i];
      soft_word.ids_g[i] = word.ids_g[i];
      soft_word.diff_ids[i] = word.diff_ids[i];
      soft_word.chars[i] = &word.chars[i];
    }
    return soft_word;
  };

  for (int i = 0; i < order; i++) {
    if (i >= 16) {
      {
        // s0
        Word &word = steps[i - 15].w;
        vector<uint32_t> id_vecs[] = {to_vec (word.ids_f),
                                      to_vec (word.ids_g),
                                      to_vec (word.diff_ids)};
        for (int k = 0; k < 3; k++) {
          vector<uint32_t> inputs[] = {
              rotate_word (id_vecs[k], -7),
              rotate_word (id_vecs[k], -18),
              rotate_word (id_vecs[k], -3, false),
          };
          for (int j = 0; j < 3; j++)
            copy (inputs[j].begin (), inputs[j].end (),
                  k == 0   ? operations[i].s0.inputs[j].ids_f
                  : k == 1 ? operations[i].s0.inputs[j].ids_g
                           : operations[i].s0.inputs[j].diff_ids);
        }

        for (int j = 0; j < 32; j++) {
          operations[i].s0.inputs[0].chars[j] =
              &word.chars[e_mod (j - 7, 32)];
          operations[i].s0.inputs[1].chars[j] =
              &word.chars[e_mod (j - 18, 32)];
          // Ensure that the first 3 chars aren't used
          operations[i].s0.inputs[2].chars[j] =
              j >= 3 ? &word.chars[e_mod (j - 3, 32)] : zero_char;
        }
      }
      {
        // s1
        Word &word = steps[i - 2].w;
        vector<uint32_t> id_vecs[] = {to_vec (word.ids_f),
                                      to_vec (word.ids_g),
                                      to_vec (word.diff_ids)};
        for (int k = 0; k < 3; k++) {
          vector<uint32_t> inputs[] = {
              rotate_word (id_vecs[k], -17),
              rotate_word (id_vecs[k], -19),
              rotate_word (id_vecs[k], -10, false),
          };
          for (int j = 0; j < 3; j++)
            copy (inputs[j].begin (), inputs[j].end (),
                  k == 0   ? operations[i].s1.inputs[j].ids_f
                  : k == 1 ? operations[i].s1.inputs[j].ids_g
                           : operations[i].s1.inputs[j].diff_ids);
        }

        for (int j = 0; j < 32; j++) {
          operations[i].s1.inputs[0].chars[j] =
              &word.chars[e_mod (j - 17, 32)];
          operations[i].s1.inputs[1].chars[j] =
              &word.chars[e_mod (j - 19, 32)];
          // Ensure that the first 10 chars aren't used
          operations[i].s1.inputs[2].chars[j] =
              j >= 10 ? &word.chars[e_mod (j - 10, 32)] : zero_char;
        }
      }
      {
        // add.W
        Word *words[] = {&steps[i].s1, &steps[i - 7].w, &steps[i].s0,
                         &steps[i - 16].w};
        for (int j = 0; j < 4; j++)
          operations[i].add_w.inputs[j] = to_soft_word (*words[j]);

        for (int j = 0; j < 2; j++)
          operations[i].add_w.carries[j] =
              to_soft_word (steps[i].add_w_r[j]);
      }
    }

    {
      // sigma0
      Word &word = steps[ABS_STEP (i - 1)].a;
      vector<uint32_t> id_vecs[] = {
          to_vec (word.ids_f), to_vec (word.ids_g), to_vec (word.diff_ids)};
      for (int k = 0; k < 3; k++) {
        vector<uint32_t> inputs[] = {
            rotate_word (id_vecs[k], -2),
            rotate_word (id_vecs[k], -13),
            rotate_word (id_vecs[k], -22),
        };
        for (int j = 0; j < 3; j++)
          copy (inputs[j].begin (), inputs[j].end (),
                k == 0   ? operations[i].sigma0.inputs[j].ids_f
                : k == 1 ? operations[i].sigma0.inputs[j].ids_g
                         : operations[i].sigma0.inputs[j].diff_ids);
      }

      for (int j = 0; j < 32; j++) {
        operations[i].sigma0.inputs[0].chars[j] =
            &word.chars[e_mod (j - 2, 32)];
        operations[i].sigma0.inputs[1].chars[j] =
            &word.chars[e_mod (j - 13, 32)];
        operations[i].sigma0.inputs[2].chars[j] =
            &word.chars[e_mod (j - 22, 32)];
      }
    }
    {
      // sigma1
      Word &word = steps[ABS_STEP (i - 1)].e;
      vector<uint32_t> id_vecs[] = {
          to_vec (word.ids_f), to_vec (word.ids_g), to_vec (word.diff_ids)};
      for (int k = 0; k < 3; k++) {
        vector<uint32_t> inputs[] = {
            rotate_word (id_vecs[k], -6),
            rotate_word (id_vecs[k], -11),
            rotate_word (id_vecs[k], -25),
        };
        for (int j = 0; j < 3; j++)
          copy (inputs[j].begin (), inputs[j].end (),
                k == 0   ? operations[i].sigma1.inputs[j].ids_f
                : k == 1 ? operations[i].sigma1.inputs[j].ids_g
                         : operations[i].sigma1.inputs[j].diff_ids);
      }

      for (int j = 0; j < 32; j++) {
        operations[i].sigma1.inputs[0].chars[j] =
            &word.chars[e_mod (j - 6, 32)];
        operations[i].sigma1.inputs[1].chars[j] =
            &word.chars[e_mod (j - 11, 32)];
        operations[i].sigma1.inputs[2].chars[j] =
            &word.chars[e_mod (j - 25, 32)];
      }
    }
    {
      // maj
      for (int j = 1; j <= 3; j++)
        operations[i].maj.inputs[j - 1] =
            to_soft_word (steps[ABS_STEP (i - j)].a);
    }
    {
      // ch
      for (int j = 1; j <= 3; j++)
        operations[i].ch.inputs[j - 1] =
            to_soft_word (steps[ABS_STEP (i - j)].e);
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
      for (int j = 0; j < 5; j++)
        operations[i].add_t.inputs[j] = to_soft_word (*words[j]);
      for (int j = 0; j < 2; j++)
        operations[i].add_t.carries[j] = to_soft_word (steps[i].add_t_r[j]);
    }
    {
      // add.E
      Word *words[] = {
          &steps[ABS_STEP (i - 4)].a,
          &steps[i].t,
      };
      for (int j = 0; j < 2; j++)
        operations[i].add_e.inputs[j] = to_soft_word (*words[j]);
      operations[i].add_e.carries[0] = to_soft_word (steps[i].add_e_r[0]);
    }
    {
      // add.A
      Word *words[] = {&steps[i].t, &steps[i].sigma0, &steps[i].maj};
      for (int j = 0; j < 3; j++)
        operations[i].add_a.inputs[j] = to_soft_word (*words[j]);
      for (int j = 0; j < 2; j++)
        operations[i].add_a.carries[j] = to_soft_word (steps[i].add_a_r[j]);
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