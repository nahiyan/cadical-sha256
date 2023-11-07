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
      {
        // add.W
        Word *words[] = {&state.steps[i].s1, &state.steps[i - 7].w,
                         &state.steps[i].s0, &state.steps[i - 16].w};
        for (int j = 0; j < 4; j++)
          operations[i].add_w.inputs[j] = words[j];
        for (int j = 0; j < 2; j++)
          operations[i].add_w.carries[j] = &state.steps[i].add_w_r[j];
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
    {
      // add.T
      Word *words[] = {
          &state.steps[ABS_STEP (i - 4)].e,
          &state.steps[i].sigma1,
          &state.steps[i].ch,
          &state.steps[i].k,
          &state.steps[i].w,
      };
      for (int j = 0; j < 5; j++)
        operations[i].add_t.inputs[j] = words[j];
      for (int j = 0; j < 2; j++)
        operations[i].add_t.carries[j] = &state.steps[i].add_t_r[j];
    }
    {
      // add.E
      Word *words[] = {
          &state.steps[ABS_STEP (i - 4)].a,
          &state.steps[i].t,
      };
      for (int j = 0; j < 2; j++)
        operations[i].add_e.inputs[j] = words[j];
      operations[i].add_e.carries[0] = &state.steps[i].add_e_r[0];
    }
    {
      // add.A
      Word *words[] = {&state.steps[i].t, &state.steps[i].sigma0,
                       &state.steps[i].maj};
      for (int j = 0; j < 3; j++)
        operations[i].add_a.inputs[j] = words[j];
      for (int j = 0; j < 2; j++)
        operations[i].add_a.carries[j] = &state.steps[i].add_a_r[j];
    }
  }
}
} // namespace SHA256