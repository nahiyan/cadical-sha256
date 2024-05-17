#include "state.hpp"
#include "1_bit/state.hpp"
#include "4_bit/state.hpp"
#include "sha256.hpp"
#include "types.hpp"
#include "util.hpp"

using namespace SHA256;

inline void State::refresh_char (Word &word, int index) {
  auto &id_f = word.ids_f[index];
  auto &id_g = word.ids_g[index];
  auto &base_id = word.char_ids[index];
  char &c = word.chars[index];
  char c_before = c;

  assert (id_f != 0 && id_g != 0 && base_id != 0);
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
      prop_markings_trail.back ().push_back ({op_id, step, pos, base_id});
#if !TWO_BIT_ADD_DIFFS
      if (op_id < op_add_w)
#endif
        two_bit_markings_trail.back ().push_back (
            {op_id, step, pos, base_id});
#if WORDWISE_PROPAGATE
      if (op_id >= op_add_w)
        marked_operations_strong_prop[op_id][step] = true;
#endif
    }
  }
}

void State::soft_refresh () {
  Timer timer (&total_refresh_time);
  for (auto &base_id : partial_assignment.updated_vars) {
    auto &info = vars_info[base_id];
    refresh_char (*info.word, info.identity.col);
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
      }
    }
  }
}

void State::print () {
  auto reverse_string = [] (string str) -> string {
    string new_str;
    for (auto it = str.end (); it-- != str.begin ();)
      new_str += *it;
    return new_str;
  };

  for (int i = -4; i < order; i++) {
    auto &step = steps[ABS_STEP (i)];
    printf (i >= 0 && i <= 9 ? " %d " : "%d ", i);
    printf ("%s %s", reverse_string (step.a.chars).c_str (),
            reverse_string (step.e.chars).c_str ());
    if (i >= 0) {
      auto &step_ = steps[i];
      printf (" %s", reverse_string (step_.w.chars).c_str ());
      if (i >= 16) {
        printf (" %s", reverse_string (step_.s0.chars).c_str ());
        printf (" %s", reverse_string (step_.s1.chars).c_str ());
      } else {
        printf ("                                 ");
        printf ("                                 ");
      }
      printf (" %s", reverse_string (step_.sigma0.chars).c_str ());
      printf (" %s", reverse_string (step_.sigma1.chars).c_str ());
      printf (" %s", reverse_string (step_.maj.chars).c_str ());
      printf (" %s", reverse_string (step_.ch.chars).c_str ());
    }
    printf ("\n");
  }
}