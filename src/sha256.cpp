#include "sha256.hpp"
#include "sha256_2_bit.hpp"
#include "sha256_propagate.hpp"
#include "sha256_state.hpp"
#include "sha256_tests.hpp"
#include "sha256_util.hpp"
#include <cassert>
#include <climits>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>
#include <string>

#define CUSTOM_BRANCHING true
#define BLOCK_INCONS true
#define BLOCK_ADDITION_INCONS true

using namespace SHA256;

int Propagator::order = 0;
State Propagator::state = State ();
uint64_t counter = 0;
Stats Propagator::stats = Stats{0, 0, 0};

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
    state.order = order;
    // Since this is the last comment, set the operations
    state.set_operations ();

    printf ("Initial state:\n");
    state.hard_refresh ();
    state.print ();

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

      if (prefix[0] == 'D')
        word.chars = string (32, '?');

      // Add the IDs
      for (int i = 31, id = value, id2 = value; i >= 0;
           i--, id++, id2 += 4) {
        if (prefix[0] == 'D') {
          word.diff_ids[i] = id2;
          for (int j = 0; j < 4; j++)
            state.id_word_rels[id2] = {&word, i};
        } else if (is_f) {
          word.ids_f[i] = id;
          state.id_word_rels[id] = {&word, i};
        } else {
          word.ids_g[i] = id;
          state.id_word_rels[id] = {&word, i};
        }
      }

      // Add to observed vars
      if (word.ids_f[0] != 0 && word.ids_g[0] != 0 && word.diff_ids[0] != 0)
        for (int i = 0; i < 32; i++) {
          solver->add_observed_var (word.ids_f[i]);
          solver->add_observed_var (word.ids_g[i]);
          for (int j = 0; j < 4; j++)
            solver->add_observed_var (word.diff_ids[i] + j);
        }
    }
  }
}

void Propagator::notify_assignment (int lit, bool is_fixed) {
  // Timer timer (&stats.total_cb_time);
  if (is_fixed)
    current_trail.front ().push_back (lit);
  else
    current_trail.back ().push_back (lit);

  // Assign variables in the partial assignment
  state.partial_assignment.set (lit);
}

void Propagator::notify_backtrack (size_t new_level) {
  // Timer timer (&stats.total_cb_time);
  while (current_trail.size () > new_level + 1) {
    // Unassign the variables that are removed from the trail
    for (auto lit : current_trail.back ())
      state.partial_assignment.unset (lit);

    current_trail.pop_back ();
  }

  // printf ("Backtracked\n");
}

void test_equations (vector<Equation> &equations);

void Propagator::notify_new_decision_level () {
  Timer timer (&stats.total_cb_time);

  current_trail.push_back (std::vector<int> ());
  counter++;

  // !Debug: 2-bit equations for 27-sfs
  // state.hard_refresh (true);
  // state.print ();
  // derive_two_bit_equations (two_bit, state);
  // test_equations (two_bit.equations[0]);
  // state.print_operations ();
  // exit (0);

  // !Debug: Periodically print the state
  // if (counter % 1000000 == 0) {
  //   printf ("Current state:\n");
  //   // state.hard_refresh (false);
  //   state.soft_refresh ();
  //   state.print ();
  // }
#if CUSTOM_BRANCHING
  if (counter % 20 != 0)
    return;
  if (!decision_lits.empty ())
    return;

  // state.refresh (false);

  // Refresh the state
  state.soft_refresh ();

  auto rand_ground_x = [] (list<int> &decision_lits, Word &word, int &j) {
    srand (clock () + j);
    if (rand () % 2 == 0) {
      // u
      decision_lits.push_back (word.ids_f[j]);
      decision_lits.push_back (-word.ids_g[j]);
    } else {
      // n
      decision_lits.push_back (-word.ids_f[j]);
      decision_lits.push_back (word.ids_g[j]);
    }
  };

  // Stage 1
  for (int i = order - 1; i >= 0; i--) {
    auto &w = state.steps[i].w;
    for (int j = 0; j < 32; j++) {
      auto &c = w.chars[j];
      // Impose '-' for '?'
      if (c == '?') {
        decision_lits.push_back ((w.diff_ids[j] + 0));
        decision_lits.push_back (-(w.diff_ids[j] + 1));
        decision_lits.push_back (-(w.diff_ids[j] + 2));
        decision_lits.push_back ((w.diff_ids[j] + 3));
        return;
      } else if (c == 'x') {
        // Impose 'u' or 'n' for '?'
        rand_ground_x (decision_lits, w, j);
        return;
      }
    }
  }

  // printf ("Stage 2\n");

  // Stage 2
  for (int i = -4; i < order; i++) {
    auto &a = state.steps[ABS_STEP (i)].a;
    auto &e = state.steps[ABS_STEP (i)].e;
    for (int j = 0; j < 32; j++) {
      auto &a_c = a.chars[j];
      auto &e_c = e.chars[j];
      if (a_c == '?') {
        decision_lits.push_back ((a.diff_ids[j] + 0));
        decision_lits.push_back (-(a.diff_ids[j] + 1));
        decision_lits.push_back (-(a.diff_ids[j] + 2));
        decision_lits.push_back ((a.diff_ids[j] + 3));
        return;
      } else if (a_c == 'x') {
        rand_ground_x (decision_lits, a, j);
        return;
      } else if (e_c == '?') {
        decision_lits.push_back ((e.diff_ids[j] + 0));
        decision_lits.push_back (-(e.diff_ids[j] + 1));
        decision_lits.push_back (-(e.diff_ids[j] + 2));
        decision_lits.push_back ((e.diff_ids[j] + 3));
        return;
      } else if (e_c == 'x') {
        rand_ground_x (decision_lits, e, j);
        return;
      }
    }
  }

  // printf ("Stage 3\n");

  // Stage 3
#if BLOCK_INCONS == false
  two_bit = TwoBit{};
  derive_two_bit_equations (two_bit, state);
#endif
  for (auto &entry : two_bit.bit_constraints_count) {
    uint32_t ids[] = {get<0> (entry.first), get<1> (entry.first),
                      get<2> (entry.first)};
    uint32_t values[] = {state.partial_assignment.get (ids[0]),
                         state.partial_assignment.get (ids[1]),
                         state.partial_assignment.get (ids[2])};
    if (values[2] == LIT_FALSE) {
      // Impose '-'
      srand (clock ());
      if (rand () % 2 == 0) {
        decision_lits.push_back (ids[0]);
        decision_lits.push_back (ids[1]);
      } else {
        decision_lits.push_back (-ids[0]);
        decision_lits.push_back (-ids[1]);
      }
      // printf ("Stage 3: guess\n");
      return;
    }
  }
#endif
}

int Propagator::cb_decide () {
  // Timer time (&stats.total_cb_time);
  if (decision_lits.empty ())
    return 0;
  int lit = decision_lits.front ();
  decision_lits.pop_front ();
  stats.decisions_count++;
  // printf ("Debug: decision %d\n", lit);
  return lit;
}

int Propagator::cb_propagate () {
  // Timer time (&stats.total_cb_time);
  if (propagation_lits.empty ())
    return 0;
  int lit = propagation_lits.back ();
  assert (lit != 0);
  propagation_lits.pop_back ();
  printf ("Debug: propagate %d\n", lit);
  return lit;
}

int Propagator::cb_add_reason_clause_lit (int propagated_lit) {
  // Timer time (&stats.total_cb_time);
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
  Timer time (&stats.total_cb_time);
#if BLOCK_INCONS
  // Check for 2-bit inconsistencies here
  if (counter % 20 != 0)
    return false;
  bool has_clause = false;

  // Weak addition propagation
#if BLOCK_ADDITION_INCONS
  prop_addition_weakly ();
  has_clause = !external_clauses.empty ();
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
    external_clauses.push_back (clause);
    printf ("Debug: keeping shortest (addition) clause of size %ld\n",
            clause.size ());
    // print (clause);
    return true;
  }
#endif

  // Get the blocking clauses
  state.soft_refresh ();
  two_bit = TwoBit{};
  derive_two_bit_equations (two_bit, state);
  // printf ("Debug: derived %ld equations\n", two_bit.equations[0].size
  // ());
  for (int block_index = 0; block_index < 2; block_index++) {
    auto confl_equations =
        check_consistency (two_bit.equations[block_index], false);
    bool is_inconsistent = !confl_equations.empty ();

    // Block inconsistencies
    if (is_inconsistent) {
      block_inconsistency (two_bit, state.partial_assignment,
                           external_clauses, block_index);
      has_clause = true;
      break;
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
    external_clauses.push_back (clause);
    printf ("Debug: keeping shortest clause of size %ld\n", clause.size ());
    // print (clause);
  }

  return has_clause;
#else
  if (!external_clauses.empty ())
    return true;
  return false;
#endif
}

int Propagator::cb_add_external_clause_lit () {
  // Timer timer (&stats.total_cb_time);
  if (external_clauses.empty ())
    return 0;

  auto &clause = external_clauses.back ();
  assert (!clause.empty ());
  int lit = clause.back ();
  clause.pop_back ();
  if (clause.empty ()) {
    external_clauses.pop_back ();
    stats.clauses_count++;
  }

  assert (lit < 0   ? state.partial_assignment.get (abs (lit)) == LIT_TRUE
          : lit > 0 ? state.partial_assignment.get (abs (lit)) == LIT_FALSE
                    : true);

  // printf ("Debug: gave EC lit %d (%d)\n", lit,
  //         state.partial_assignment.get (abs (lit)));
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

  for (auto &equation : equations)
    cout << equation.names[0] << " " << (equation.diff == 0 ? "=" : "=/=")
         << " " << equation.names[1] << endl;

  cout << "Found " << found_equations.size () << " equations" << endl;
  for (auto &equation : found_equations)
    cout << equation.names[0] << " " << (equation.diff == 0 ? "=" : "=/=")
         << " " << equation.names[1] << endl;
}
