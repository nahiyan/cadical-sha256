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
      if (prefix[0] == 'D')
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
}

void Propagator::notify_assignment (int lit, bool is_fixed) {
  if (is_fixed)
    current_trail.front ().push_back (lit);
  else
    current_trail.back ().push_back (lit);

  // Assign variables in the partial assignment
  partial_assignment.set (lit);

  // printf ("Debug: %d %d %d %d\n", lit, is_fixed, partial_assignment.get
  // (1),
  //         partial_assignment.get (2));
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
    for (int i = 0; i < 32; i++) {
      get_chars (step.a, partial_assignment);
    }
  }
}

void Propagator::print_state () {
  for (int i = -4; i < Propagator::order; i++) {
    auto step = Propagator::state.steps[STEP (i)];
    printf ("%d\t%s", i, step.a.chars);
    if (i < 0) {
      printf ("\n");
      continue;
    }
    printf ("\n");
  }
  exit (0);
}