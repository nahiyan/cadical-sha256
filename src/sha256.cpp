#include "sha256.hpp"
#include "sha256_2_bit.hpp"
#include "sha256_propagate.hpp"
#include "sha256_tests.hpp"
#include "sha256_util.hpp"
#include <cassert>
#include <climits>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>

#define SKIPS 500 - 1

using namespace SHA256;
using namespace std;

int Propagator::order = 0;
State Propagator::state = State{};
Operations Propagator::operations[64];
int64_t counter = SKIPS;
Stats Propagator::stats = Stats{0};

Propagator::Propagator (CaDiCaL::Solver *solver) {
#ifndef NDEBUG
  run_tests ();
  // exit (0);
#endif
  this->solver = solver;
  solver->connect_external_propagator (this);
  printf ("Connected!\n");
  current_trail.push_back (std::vector<int> ());
  load_prop_rules ("prop-rules.db");
  load_two_bit_rules ("2-bit-rules.db");
}

void Propagator::parse_comment_line (string line,
                                     CaDiCaL::Solver *&solver) {
  istringstream iss (line);
  string key;
  int value;
  iss >> key >> value;

  // Determine the order
  if (key == "order") {
    order = value;

    // Since this is the last comment, set the operations
    set_operations ();

    return;
  }

  // Get the step
  regex pattern ("(.+_)(\\d+)_[fg]");
  smatch match;
  int step;
  string actual_prefix;
  if (regex_search (key, match, pattern)) {
    actual_prefix = match[1];
    step = stoi (match[2].str ());
  } else {
    // printf ("Warning: Failed to load IDs from %s\n", key.c_str ());
    return;
  }

  // Determine the block
  bool is_f = key.back () == 'f';

  // Pair the prefixes with the words
  vector<pair<string, Word &>> prefix_pairs = {
      {"A_", state.steps[step].a},
      {"E_", state.steps[step].e},
      {"W_", state.steps[step].w},
      {"s0_", state.steps[step].s0},
      {"s1_", state.steps[step].s1},
      {"sigma0_", state.steps[step].sigma0},
      {"sigma1_", state.steps[step].sigma1},
      {"maj_", state.steps[step].maj},
      {"if_", state.steps[step].ch},
      {"T_", state.steps[step].t},
      {"K_", state.steps[step].k},
      {"add.W.r0_", state.steps[step].add_w_r[0]},
      {"add.W.r1_", state.steps[step].add_w_r[1]},
      {"add.T.r0_", state.steps[step].add_t_r[0]},
      {"add.T.r1_", state.steps[step].add_t_r[1]},
      {"add.E.r0_", state.steps[step].add_e_r[0]},
      {"add.A.r0_", state.steps[step].add_a_r[0]},
      {"add.A.r1_", state.steps[step].add_a_r[1]},
  };

  for (auto &pair : prefix_pairs) {
    auto &word = pair.second;
    string prefixes[] = {pair.first, 'D' + pair.first};

    for (auto &prefix : prefixes) {
      if (prefix != actual_prefix)
        continue;

      // Add the IDs
      for (int i = 31, id = value; i >= 0; i--, id++) {
        if (prefix[0] == 'D')
          word.diff_ids[i] = id;
        else if (is_f)
          word.ids_f[i] = id;
        else
          word.ids_g[i] = id;
      }

      // Add to observed vars
      if (word.ids_f[0] != 0 && word.ids_g[0] != 0 && word.diff_ids[0] != 0)
        for (int i = 0; i < 32; i++) {
          solver->add_observed_var (word.ids_f[i]);
          solver->add_observed_var (word.ids_g[i]);
          solver->add_observed_var (word.diff_ids[i]);
        }
    }
  }
}

void Propagator::notify_assignment (int lit, bool is_fixed) {
  if (is_fixed)
    current_trail.front ().push_back (lit);
  else
    current_trail.back ().push_back (lit);

  // Assign variables in the partial assignment
  partial_assignment.set (lit);
  // printf ("BCP: %d\n", lit);
}

void Propagator::notify_backtrack (size_t new_level) {
  while (current_trail.size () > new_level + 1) {
    // Unassign the variables that are removed from the trail
    for (auto lit : current_trail.back ())
      partial_assignment.unset (lit);

    current_trail.pop_back ();
  }

  // printf ("Backtracked\n");
}

void test_equations (vector<Equation> &equations);

void Propagator::notify_new_decision_level () {
  current_trail.push_back (std::vector<int> ());
  // printf ("New decision level\n");
  // if (++counter % 1000 != 0) {
  //   return;
  // }
  // refresh_state ();
  // derive_two_bit_equations (two_bit.equations, state, operations, order);
  // test_equations (two_bit.equations[0]);
  // print_state ();
  // printf ("Debug: equations count = %ld\n", two_bit.equations[0].size
  // ());

  // prop_addition_weakly ();
}

int Propagator::cb_decide () {
  if (decision_lits.empty ())
    return 0;
  int lit = decision_lits.back ();
  decision_lits.pop_back ();
  printf ("Debug: decision %d\n", lit);
  return lit;
}
int Propagator::cb_propagate () {
  if (propagation_lits.empty ())
    return 0;
  int lit = propagation_lits.back ();
  assert (lit != 0);
  propagation_lits.pop_back ();
  printf ("Debug: propagate %d\n", lit);
  return lit;
}

int Propagator::cb_add_reason_clause_lit (int propagated_lit) {
  if (reason_clauses.find (propagated_lit) == reason_clauses.end ())
    return 0;

  auto &reason_clause = reason_clauses[propagated_lit];
  int lit = reason_clause.back ();
  reason_clause.pop_back ();
  if (reason_clause.size () == 0)
    reason_clauses.erase (propagated_lit);
  printf ("Debug: asked for reason clause %d: %d\n", propagated_lit, lit);
  return lit;
}

bool Propagator::cb_has_external_clause () {
  // printf ("Debug: has external clause?\n");
  // Check for 2-bit inconsistencies here
  if (counter != SKIPS) {
    counter++;
    return false;
  }
  counter = 0;
  bool has_clause = false;
  two_bit = TwoBit{};

  // Get the blocking clauses
  auto start_time = clock ();
  refresh_state ();
  derive_two_bit_equations (two_bit, state, operations, order);
  printf ("Debug: derived %ld equations\n", two_bit.equations[0].size ());
  for (int block_index = 0; block_index < 2; block_index++) {
    auto confl_equations =
        check_consistency (two_bit.equations[block_index], false);
    bool is_inconsistent = !confl_equations.empty ();

    // Block inconsistencies
    if (is_inconsistent) {
      block_inconsistency (two_bit, partial_assignment, external_clauses,
                           block_index);
      has_clause = true;
    }
  }
  // Keep only the shortest clause
  if (has_clause) {
    int shortest_index = -1, shortest_length = INT_MAX;
    for (int i = 0; i < int (external_clauses.size ()); i++) {
      int size = external_clauses[i].size ();
      if (size >= shortest_length)
        continue;

      shortest_length = size;
      shortest_index = i;
    }
    auto clause = external_clauses[shortest_index];
    external_clauses.clear ();
    // if (clause.size () <= 20) {
    external_clauses.push_back (clause);
    printf ("Debug: keeping shortest clause of size %ld: ", clause.size ());
    // } else {
    //   has_clause = false;
    // }
    print (clause);
  }

  if (has_clause)
    counter = SKIPS;

  stats.total_cb_time += clock () - start_time;
  return has_clause;
}

int Propagator::cb_add_external_clause_lit () {
  if (external_clauses.empty ())
    return 0;

  auto &clause = external_clauses.back ();
  int lit = clause.back ();
  clause.pop_back ();
  if (clause.empty ())
    external_clauses.pop_back ();
  printf ("Debug: gave EC lit %d (%d)\n", lit,
          partial_assignment.get (abs (lit)));
  return lit;
}

// !Debug
void test_equations (vector<Equation> &equations) {
  std::ifstream file ("equations.txt");
  std::string line;
  std::regex pattern ("Equation\\(x='(.*?)', y='(.*?)', diff=(.*?)\\)");
  vector<Equation> found_equations;
  while (getline (file, line)) {
    std::smatch match;
    if (regex_search (line, match, pattern)) {
      if (match.size () == 4) {
        std::string x = match[1];
        std::string y = match[2];
        int diff = std::stoi (match[3]);

        for (auto &equation : equations) {
          if (equation.diff == diff &&
              ((equation.names[0] == x && equation.names[1] == y) ||
               (equation.names[1] == x && equation.names[0] == y)))
            found_equations.push_back (equation);
        }
      }
    } else {
      std::cout << "No match found." << std::endl;
    }
  }

  cout << "Unmatched equations: "
       << equations.size () - found_equations.size () << endl;

  cout << "Found " << found_equations.size () << " equations" << endl;
  for (auto &equation : found_equations)
    cout << equation.names[0] << " " << (equation.diff == 0 ? "=" : "=/=")
         << " " << equation.names[1] << endl;
}

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

  // !Debug
  exit (0);
}
