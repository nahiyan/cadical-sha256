#include "sha256.hpp"
#include "sha256_propagate.hpp"
#include "sha256_util.hpp"

using namespace SHA256;

void refresh_chars (Word &word, PartialAssignment &partial_assignment) {
  word.chars = string (32, '?');
  for (int i = 0; i < 32; i++) {
    auto id_f = word.ids_f[i];
    auto id_g = word.ids_g[i];
    auto diff_id = word.diff_ids[i];
    char &c = word.chars[i];

    if (id_f == 0 || id_g == 0 || diff_id == 0) {
      c = '?';
      continue;
    }

    uint8_t values[3] = {partial_assignment.get (id_f),
                         partial_assignment.get (id_g),
                         partial_assignment.get (diff_id)};

    if (values[0] == LIT_UNDEF && values[1] == LIT_UNDEF &&
        values[2] != LIT_UNDEF)
      c = values[2] == LIT_TRUE ? 'x' : '-';
    else if (values[2] == LIT_TRUE &&
             (values[0] == LIT_TRUE || values[1] == LIT_FALSE))
      c = 'u';
    else if (values[2] == LIT_TRUE &&
             (values[0] == LIT_FALSE || values[1] == LIT_TRUE))
      c = 'n';
    else if (values[2] == LIT_FALSE &&
             (values[0] == LIT_TRUE || values[1] == LIT_TRUE))
      c = '1';
    else if (values[2] == LIT_FALSE &&
             (values[0] == LIT_FALSE || values[1] == LIT_FALSE))
      c = '0';
    else
      c = '?';
  }
}

void Propagator::refresh_state () {
  for (int i = -4; i < order; i++) {
    // step < 0
    auto &step = state.steps[ABS_STEP (i)];
    refresh_chars (step.a, partial_assignment);
    refresh_chars (step.e, partial_assignment);

    if (i >= 0) {
      auto &step = state.steps[i];
      refresh_chars (step.w, partial_assignment);
      refresh_chars (step.sigma0, partial_assignment);
      refresh_chars (step.sigma1, partial_assignment);
      refresh_chars (step.ch, partial_assignment);
      refresh_chars (step.maj, partial_assignment);
      refresh_chars (step.k, partial_assignment);
      refresh_chars (step.t, partial_assignment);
      refresh_chars (step.add_t_r[0], partial_assignment);
      refresh_chars (step.add_t_r[1], partial_assignment);
      refresh_chars (step.add_e_r[0], partial_assignment);
      refresh_chars (step.add_a_r[0], partial_assignment);
      refresh_chars (step.add_a_r[1], partial_assignment);

      // Operation inputs
      for (int j = 0; j < 3; j++) {
        refresh_chars (operations[i].sigma0.inputs[j], partial_assignment);
        refresh_chars (operations[i].sigma1.inputs[j], partial_assignment);
        refresh_chars (operations[i].maj.inputs[j], partial_assignment);
        refresh_chars (operations[i].ch.inputs[j], partial_assignment);
      }

      if (i >= 16) {
        refresh_chars (step.s0, partial_assignment);
        refresh_chars (step.s1, partial_assignment);
        refresh_chars (step.add_w_r[0], partial_assignment);
        refresh_chars (step.add_w_r[1], partial_assignment);

        // Operation inputs
        for (int j = 0; j < 3; j++) {
          refresh_chars (operations[i].s0.inputs[j], partial_assignment);
          refresh_chars (operations[i].s1.inputs[j], partial_assignment);
        }

        {
          // s0
          vector<string> inputs (3);
          for (int j = 0; j < 3; j++)
            inputs[j] = operations[i].s0.inputs[j].chars;

          step.s0.chars =
              propagate (IO_PROP_XOR3_ID, inputs, step.s0.chars);
        }
        {
          // s1
          vector<string> inputs (3);
          for (int j = 0; j < 3; j++)
            inputs[j] = operations[i].s1.inputs[j].chars;
          step.s1.chars =
              propagate (IO_PROP_XOR3_ID, inputs, step.s1.chars);
        }

        prop_with_int_diff (ADD_W_ID, {
                                          &state.steps[i].w.chars,
                                          &state.steps[i].s1.chars,
                                          &state.steps[i - 7].w.chars,
                                          &state.steps[i].s0.chars,
                                          &state.steps[i - 16].w.chars,
                                      });
      }

      {
        // sigma0
        vector<string> inputs (3);
        for (int j = 0; j < 3; j++)
          inputs[j] = operations[i].sigma0.inputs[j].chars;
        step.sigma0.chars =
            propagate (IO_PROP_XOR3_ID, inputs, step.sigma0.chars);
      }
      {
        // sigma1
        vector<string> inputs (3);
        for (int j = 0; j < 3; j++)
          inputs[j] = operations[i].sigma1.inputs[j].chars;
        step.sigma1.chars =
            propagate (IO_PROP_XOR3_ID, inputs, step.sigma1.chars);
      }

      {
        // maj
        vector<string> inputs (3);
        for (int j = 0; j < 3; j++)
          inputs[j] = operations[i].maj.inputs[j].chars;
        step.maj.chars = propagate (IO_PROP_MAJ_ID, inputs, step.maj.chars);
      }
      {
        // ch
        vector<string> inputs (3);
        for (int j = 0; j < 3; j++)
          inputs[j] = operations[i].ch.inputs[j].chars;
        step.ch.chars = propagate (IO_PROP_CH_ID, inputs, step.ch.chars);
      }

      prop_with_int_diff (ADD_E_ID,
                          {
                              &state.steps[ABS_STEP (i)].e.chars,
                              &state.steps[ABS_STEP (i - 4)].a.chars,
                              &state.steps[ABS_STEP (i - 4)].e.chars,
                              &state.steps[i].sigma1.chars,
                              &state.steps[i].ch.chars,
                              &state.steps[i].w.chars,
                          });
      prop_with_int_diff (ADD_A_ID,
                          {
                              &state.steps[ABS_STEP (i)].a.chars,
                              &state.steps[ABS_STEP (i)].e.chars,
                              &state.steps[ABS_STEP (i - 4)].a.chars,
                              &state.steps[i].sigma0.chars,
                              &state.steps[i].maj.chars,
                          });
    }
  }
}

void Propagator::print_state () {
  // if (++counter % 300 != 0)
  //   return;

  for (int i = -4; i < Propagator::order; i++) {
    auto &step = state.steps[ABS_STEP (i)];
    printf ("%d", i);
    printf (i < 0 || i > 9 ? " " : "  ");
    printf ("%s %s", step.a.chars.c_str (), step.e.chars.c_str ());
    if (i >= 0) {
      auto &step_ = state.steps[i];
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