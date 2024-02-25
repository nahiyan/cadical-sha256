#ifndef _sha256_1_bit_mendel_branch_hpp_INCLUDED
#define _sha256_1_bit_mendel_branch_hpp_INCLUDED

#include "../sha256.hpp"
#include "../state.hpp"
#include "../util.hpp"
#include "2_bit.hpp"
#include <string>

using namespace std;

namespace SHA256 {
inline void mendel_branch_1bit (State &state, list<int> &decision_lits,
                                list<list<Equation>> &equations_trail,
                                Stats &stats) {
  state.soft_refresh ();

  auto rand_ground_x = [&state] (list<int> &decision_lits, Word &word,
                                 int &j) {
    srand (clock () + j);
    if (rand () % 2 == 0) {
      // u
      if (state.partial_assignment.get (word.ids_f[j]) == LIT_UNDEF)
        decision_lits.push_back (word.ids_f[j]);
      else
        decision_lits.push_back (-word.ids_g[j]);
    } else {
      // n
      if (state.partial_assignment.get (word.ids_f[j]) == LIT_UNDEF)
        decision_lits.push_back (-word.ids_f[j]);
      else
        decision_lits.push_back (word.ids_g[j]);
    }
    assert (state.partial_assignment.get (abs (decision_lits.back ())) ==
            LIT_UNDEF);
  };

  auto ground_xnor = [&state] (list<int> &decision_lits, Word &word,
                               int &j) {
    decision_lits.push_back (-word.char_ids[j]);
    assert (state.partial_assignment.get (abs (decision_lits.back ())) ==
            LIT_UNDEF);
  };

  // Stage 1
  for (int i = state.order - 1; i >= 0; i--) {
    auto &w = state.steps[i].w;
    for (int j = 0; j < 32; j++) {
      auto &c = w.chars[j];
      // Impose '-' for '?'
      if (c == '?') {
        ground_xnor (decision_lits, w, j);
        // printf ("Stage 1: Decision\n");
        return;
      } else if (c == 'x') {
        // Impose 'u' or 'n' for 'x'
        rand_ground_x (decision_lits, w, j);
        // printf ("Stage 1: Decision\n");
        return;
      }
    }
  }

  // Stage 2
  for (int i = -4; i < state.order; i++) {
    auto &a = state.steps[ABS_STEP (i)].a;
    for (int j = 0; j < 32; j++) {
      auto &c = a.chars[j];
      if (c == '?') {
        ground_xnor (decision_lits, a, j);
        // printf ("Stage 2: Decision on A\n");
        return;
      } else if (c == 'x') {
        rand_ground_x (decision_lits, a, j);
        // printf ("Stage 2: Decision on A\n");
        return;
      }
    }
  }
  for (int i = -4; i < state.order; i++) {
    auto &e = state.steps[ABS_STEP (i)].e;
    for (int j = 0; j < 32; j++) {
      auto &c = e.chars[j];
      if (c == '?') {
        ground_xnor (decision_lits, e, j);
        // printf ("Stage 2: Decision on E\n");
        return;
      } else if (c == 'x') {
        rand_ground_x (decision_lits, e, j);
        // printf ("Stage 2: Decision on E\n");
        return;
      }
    }
  }

  // Stage 3
#if MENDEL_BRANCHING_STAGE_3
  derive_2bit_equations_1bit (state, equations_trail.back ());
  for (auto &level : equations_trail) {
    for (auto &equation : level) {
      uint32_t ids[] = {equation.ids[0], equation.ids[1]};
      for (int x = 0; x < 2; x++) {
        auto &var_info = state.vars_info[ids[x]];
        auto &col = var_info.identity.col;
        auto &word = var_info.word;
        if (word->char_ids[31 - col] != '-')
          continue;
        assert (31 - col >= 0 && 31 - col <= 31);
        assert (word->ids_f[31 - col] == ids[x] ||
                word->ids_g[31 - col] == ids[x]);
        srand (clock () + x);
        if (rand () % 2 == 0)
          decision_lits.push_back (ids[x]);
        else
          decision_lits.push_back (-ids[x]);
        // printf ("Stage 3: Decision\n");
        stats.mendel_branching_stage3_count++;
        return;
      }
    }
  }
#endif
}
} // namespace SHA256

#endif