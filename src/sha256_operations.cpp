#include "sha256.hpp"
#include "sha256_util.hpp"

namespace SHA256 {
void Propagator::set_operations () {
  auto to_vec = [] (uint32_t *ids) {
    vector<uint32_t> vec (32);
    for (int i = 0; i < 32; i++)
      vec[i] = ids[i];
    return vec;
  };

  for (int i = 0; i < order; i++) {
    if (i >= 16) {
      {
        // s0
        Word &word = state.steps[i - 15].w;
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
      }
      {
        // s1
        Word &word = state.steps[i - 2].w;
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
      }
    }

    {
      // sigma0
      Word &word = state.steps[ABS_STEP (i - 1)].a;
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
    }
    {
      // sigma1
      Word &word = state.steps[ABS_STEP (i - 1)].e;
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
    }
    {
      // maj
      Word words[] = {state.steps[ABS_STEP (i - 1)].a,
                      state.steps[ABS_STEP (i - 2)].a,
                      state.steps[ABS_STEP (i - 3)].a};
      for (int j = 0; j < 3; j++)
        for (int k = 0; k < 32; k++) {
          operations[i].maj.inputs[j].ids_f[k] = words[j].ids_f[k];
          operations[i].maj.inputs[j].ids_g[k] = words[j].ids_g[k];
          operations[i].maj.inputs[j].diff_ids[k] = words[j].diff_ids[k];
        }
    }
    {
      // ch
      Word words[] = {state.steps[ABS_STEP (i - 1)].e,
                      state.steps[ABS_STEP (i - 2)].e,
                      state.steps[ABS_STEP (i - 3)].e};
      for (int j = 0; j < 3; j++)
        for (int k = 0; k < 32; k++) {
          operations[i].ch.inputs[j].ids_f[k] = words[j].ids_f[k];
          operations[i].ch.inputs[j].ids_g[k] = words[j].ids_g[k];
          operations[i].ch.inputs[j].diff_ids[k] = words[j].diff_ids[k];
        }
    }
  }
}
} // namespace SHA256