#include "sha256.hpp"
#include "sha256_propagate.hpp"
#include "sha256_tests.hpp"
#include <cassert>
#include <cstdio>
#include <regex>
#include <string>

using namespace SHA256;
using namespace std;

int Propagator::order = 0;
State Propagator::state = State{};

Propagator::Propagator (CaDiCaL::Solver *solver) {
#ifndef NDEBUG
  run_tests ();
  exit (0);
#endif

  this->solver = solver;
  solver->connect_external_propagator (this);
  printf ("Connected!\n");
  current_trail.push_back (std::vector<int> ());
}

void Propagator::add_observed_vars (Word *word, CaDiCaL::Solver *&solver) {
  for (int i = 0; i < 32; i++) {
    solver->add_observed_var (word->ids_f[i]);
    solver->add_observed_var (word->ids_g[i]);
    solver->add_observed_var (word->diff_ids[i]);
  }
}

void Propagator::parse_comment_line (string line,
                                     CaDiCaL::Solver *&solver) {
  istringstream iss (line);
  string key;
  int value;
  iss >> key >> value;

  auto add_vars = [] (string prefix, string key, int value, bool is_f,
                      CaDiCaL::Solver *&solver) {
    if (has_prefix (prefix, key)) {
      // Get the step number
      regex pattern ("_(\\d+)_[fg]");
      smatch match;
      int step;
      if (regex_search (key, match, pattern)) {
        step = stoi (match[1].str ());
      } else {
        printf ("Warning: Failed to load IDs from %s\n", key.c_str ());
        return;
      }

      // Get the word
      Word *word = NULL;
      if (prefix == "A_" || prefix == "DA_")
        word = &state.steps[step].a;
      else if (prefix == "E_" || prefix == "DE_")
        word = &state.steps[step].e;
      else if (prefix == "W_" || prefix == "DW_")
        word = &state.steps[step].w;
      else if (prefix == "s0_" || prefix == "Ds0_")
        word = &state.steps[step].s0;
      else if (prefix == "s1_" || prefix == "Ds1_")
        word = &state.steps[step].s1;
      else if (prefix == "sigma0_" || prefix == "Dsigma0_")
        word = &state.steps[step].sigma0;
      else if (prefix == "sigma1_" || prefix == "Dsigma1_")
        word = &state.steps[step].sigma1;
      else if (prefix == "if_" || prefix == "Dif_")
        word = &state.steps[step].ch;
      else if (prefix == "maj_" || prefix == "Dmaj_")
        word = &state.steps[step].maj;

      // Add the IDs
      for (int i = 31, id = value; i >= 0; i--, id++) {
        if (prefix[0] == 'D')
          word->diff_ids[i] = id;
        else if (is_f)
          word->ids_f[i] = id;
        else
          word->ids_g[i] = id;
      }

      // Add to observed vars
      if (word->ids_f[0] != 0 && word->ids_g[0] != 0 &&
          word->diff_ids[0] != 0)
        add_observed_vars (word, solver);
    }
  };

  // Determine the order
  if (has_prefix ("DW_", key))
    Propagator::order =
        max (std::stoi (key.substr (3)) + 1, Propagator::order);

  // Determine the block
  bool is_f = key.back () == 'f';

  // A
  add_vars ("A_", key, value, is_f, solver);
  add_vars ("DA_", key, value, is_f, solver);
  // E
  add_vars ("E_", key, value, is_f, solver);
  add_vars ("DE_", key, value, is_f, solver);
  // W
  add_vars ("W_", key, value, is_f, solver);
  add_vars ("DW_", key, value, is_f, solver);
  // s0
  // add_vars ("s0_", key, value, is_f, solver);
  // add_vars ("Ds0_", key, value, is_f, solver);
  // // s1
  // add_vars ("s1_", key, value, is_f, solver);
  // add_vars ("Ds1_", key, value, is_f, solver);
  // // sigma0
  // add_vars ("sigma0_", key, value, is_f, solver);
  // add_vars ("Dsigma0_", key, value, is_f, solver);
  // // sigma1
  // add_vars ("sigma1_", key, value, is_f, solver);
  // add_vars ("Dsigma1_", key, value, is_f, solver);
  // // if
  // add_vars ("if_", key, value, is_f, solver);
  // add_vars ("Dif_", key, value, is_f, solver);
  // // maj
  // add_vars ("maj_", key, value, is_f, solver);
  // add_vars ("Dmaj_", key, value, is_f, solver);
}

void Propagator::notify_assignment (int lit, bool is_fixed) {
  if (is_fixed)
    current_trail.front ().push_back (lit);
  else
    current_trail.back ().push_back (lit);

  // Assign variables in the partial assignment
  partial_assignment.set (lit);
}

void Propagator::notify_backtrack (size_t new_level) {
  while (current_trail.size () > new_level + 1) {
    // Unassign the variables that are removed from the trail
    for (auto lit : current_trail.back ()) {
      partial_assignment.unset (lit);
    }
    current_trail.pop_back ();
  }

  // TODO: Refresh state
  refresh_state ();
}

void Propagator::notify_new_decision_level () {
  current_trail.push_back (std::vector<int> ());
  // TODO: Refresh state
  refresh_state ();
  print_state ();
}

void Propagator::refresh_state () {
  auto get_chars = [] (Word &word, PartialAssignment &partial_assignment) {
    for (int i = 0; i < 32; i++) {
      auto id_f = word.ids_f[i];
      auto id_g = word.ids_g[i];
      auto diff_id = word.diff_ids[i];
      uint8_t values[3] = {partial_assignment.get (id_f),
                           partial_assignment.get (id_g),
                           partial_assignment.get (diff_id)};

      char &c = word.chars[i];

      // printf ("%d %d %d\n", values[0], values[1], values[2]);

      if (values[0] == LIT_UNDEF && values[1] == LIT_UNDEF &&
          values[2] != LIT_UNDEF) {
        c = values[2] == LIT_TRUE ? 'x' : '-';
      } else if (values[2] == LIT_TRUE &&
                 (values[0] == LIT_TRUE || values[1] == LIT_FALSE)) {
        c = 'u';
      } else if (values[2] == LIT_TRUE &&
                 (values[0] == LIT_FALSE || values[1] == LIT_TRUE)) {
        c = 'n';
      } else if (values[2] == LIT_FALSE &&
                 (values[0] == LIT_TRUE || values[1] == LIT_TRUE)) {
        c = '1';
      } else if (values[2] == LIT_FALSE &&
                 (values[0] == LIT_FALSE || values[1] == LIT_FALSE)) {
        c = '0';
      } else {
        c = '?';
      }
    }
  };

  for (int i = -4; i < Propagator::order; i++) {
    auto &step = Propagator::state.steps[STEP (i)];
    get_chars (step.a, partial_assignment);
    get_chars (step.e, partial_assignment);
    auto &step_ = Propagator::state.steps[i];
    if (i >= 0) {
      get_chars (step_.w, partial_assignment);
      get_chars (step_.s0, partial_assignment);
      get_chars (step_.s1, partial_assignment);
      get_chars (step_.sigma0, partial_assignment);
      get_chars (step_.sigma1, partial_assignment);
      get_chars (step_.ch, partial_assignment);
      get_chars (step_.maj, partial_assignment);
    }
  }
}

void Propagator::print_state () {
  if (++tmp % 300 != 0)
    return;

  auto c_str = [] (char *chars) {
    string s;
    for (int i = 0; i < 32; i++) {
      s += chars[i];
    }
    return s;
  };

  for (int i = -4; i < Propagator::order; i++) {
    auto &step = Propagator::state.steps[STEP (i)];
    printf ("%d", i);
    printf (i < 0 || i > 9 ? " " : "  ");
    printf ("%s %s", c_str (step.a.chars).c_str (),
            c_str (step.e.chars).c_str ());
    if (i < 0) {
      printf ("\n");
      continue;
    }
    auto &step_ = Propagator::state.steps[i];
    printf (" %s", c_str (step_.w.chars).c_str ());
    printf (" %s", c_str (step_.s0.chars).c_str ());
    printf (" %s", c_str (step_.s1.chars).c_str ());
    printf (" %s", c_str (step_.sigma0.chars).c_str ());
    printf (" %s", c_str (step_.sigma1.chars).c_str ());
    printf (" %s", c_str (step_.maj.chars).c_str ());
    printf (" %s", c_str (step_.ch.chars).c_str ());
    printf ("\n");
  }
  // exit (0);
}