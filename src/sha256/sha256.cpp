#include "sha256.hpp"
#include "1_bit/2_bit.hpp"
#include "1_bit/encoding.hpp"
#include "1_bit/mendel_branch.hpp"
#include "1_bit/propagate.hpp"
#include "1_bit/strong_propagate.hpp"
#include "2_bit.hpp"
#include "4_bit/2_bit.hpp"
#include "4_bit/encoding.hpp"
#include "4_bit/propagate.hpp"
#include "lru_cache.hpp"
#include "state.hpp"
#include "strong_propagate.hpp"
#include "tests.hpp"
#include "types.hpp"
#include "util.hpp"
#include <cassert>
#include <climits>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>
#include <string>

using namespace SHA256;

State Propagator::state = State ();
uint64_t prop_counter = 0;
uint64_t block_counter = 0;
uint64_t mendel_branch_counter = 0;
Stats Propagator::stats = Stats{};

Propagator::Propagator (CaDiCaL::Solver *solver) {
#ifndef NDEBUG
  run_tests ();
#endif
  this->solver = solver;
  solver->connect_external_propagator (this);
  printf ("Connected!\n");
  state.current_trail.push_back ({});
  two_bit.equations_trail.push_back ({});
  state.prop_markings_trail.push_back ({});
  state.two_bit_markings_trail.push_back ({});
  // load_prop_rules ();
  // load_two_bit_rules ();

#if CUSTOM_PROP
  printf ("Custom propagation turned on.\n");
#endif
#if CUSTOM_BLOCKING
  printf ("Custom blocking turned on.\n");
#endif
#if STRONG_PROPAGATE
  printf ("Strong propagation (branch-based) turned on.\n");
#endif
#if TWO_BIT_ADD_DIFFS
  printf ("2-bit addition differentials turned on.\n");
#endif
#if MENDEL_BRANCHING
  printf ("Mendel's branching turned on (%d stage[s]).\n",
          MENDEL_BRANCHING_STAGES);
#endif

#ifdef LOGGING
  printf ("Logging is enabled!\n");
#endif
}

void Propagator::parse_comment_line (string line,
                                     CaDiCaL::Solver *&solver) {
#if IS_4BIT
  add_4bit_variables (line, solver);
#else
  add_1bit_variables (line, solver);
#endif
}

void Propagator::notify_assignment (int lit, bool is_fixed) {
  // Timer timer (&stats.total_cb_time);
  if (is_fixed) {
    state.current_trail.front ().push_back (lit);
    state.vars_info[abs (lit)].is_fixed = true;
  } else
    state.current_trail.back ().push_back (lit);

  // Assign the variable in the partial assignment
  state.partial_assignment.set (lit);
  // printf ("Assign %d (%c%c) in level %ld\n", lit,
  //         solver->is_decision (lit) ? 'd' : 'p', is_fixed ? 'f' : 'l',
  //         state.current_trail.size () - 1);
}

void Propagator::notify_backtrack (size_t new_level) {
  // Timer timer (&stats.total_cb_time);
  while (state.current_trail.size () > new_level + 1) {
    // Unassign the variables that are removed from the trail
    auto &level = state.current_trail.back ();
    for (auto &lit : level) {
      state.partial_assignment.unset (lit);
      // printf ("Unassign %d (%ld)\n", lit, state.current_trail.size () -
      // 1);
    }

    // Remove 2-bit edges from the graph
    for (auto &equation : two_bit.equations_trail.back ())
      two_bit.graph.remove_edge (equation.ids[0], equation.ids[1],
                                 equation.diff, &equation.antecedent);

    state.current_trail.pop_back ();
    two_bit.equations_trail.pop_back ();
    state.prop_markings_trail.pop_back ();
    state.two_bit_markings_trail.pop_back ();
  }
  assert (!state.current_trail.empty ());

  // Remove reasons that no longer hold
  for (auto &p_lit : propagation_lits) {
    auto reason_it = reasons.find (p_lit);
    if (reason_it == reasons.end ())
      continue;

    // Remove reason if it doesn't hold anymore
    for (auto &lit : reason_it->second.antecedent) {
      auto value = state.partial_assignment.get (abs (lit));
      if (value == LIT_UNDEF) {
        reasons.erase (reason_it);
        break;
      }
    }
  }
}

void Propagator::notify_new_decision_level () {
  state.current_trail.push_back ({});
  two_bit.equations_trail.push_back ({});
  state.prop_markings_trail.push_back ({});
  state.two_bit_markings_trail.push_back ({});
}

int Propagator::cb_decide () {
  Timer timer (&stats.total_cb_time);

#if MENDEL_BRANCHING
  // if (++mendel_branch_counter % 20 == 0) {
  if (decision_lits.empty ()) {
    state.soft_refresh ();
    Timer *mb_timer = new Timer (&stats.total_mendel_branch_time);
#if IS_4BIT
    mendel_branch_4bit (state, decision_lits, two_bit.equations_trail,
                        two_bit, stats);
#else
    mendel_branch_1bit (state, decision_lits, two_bit.equations_trail,
                        two_bit, stats);
#endif
    delete mb_timer;
    stats.mendel_branching_decisions_count += decision_lits.size ();
  }
  // }
#endif

  if (decision_lits.empty ())
    return 0;
  int &lit = decision_lits.front ();
  assert (state.partial_assignment.get (abs (lit)) == LIT_UNDEF);
  decision_lits.pop_front ();
  stats.decisions_count++;
  // printf ("Debug: decision %d\n", lit);

  return lit;
}

inline bool Propagator::custom_block () {
  state.soft_refresh ();
  Timer timer (&stats.total_two_bit_derive_time);
  int trail_level = int (two_bit.equations_trail.size () - 1);
#if IS_4BIT
  derive_2bit_equations_4bit (state, two_bit.equations_trail.back (),
                              stats);
#else
  derive_2bit_equations_1bit (state, two_bit.equations_trail.back (),
                              two_bit, trail_level, stats);
#endif

  int shortest_l_graph_based = INT_MAX;
  unordered_set<int> shortest_c_graph_based;
  for (auto &entry : two_bit.blocking_clauses) {
    if (entry.second >= trail_level) {
      printf ("Graph: b. clause (size %ld): ", entry.first.size ());
      for (auto &lit : entry.first)
        assert (state.partial_assignment.get (abs (lit)) ==
                (lit > 0 ? LIT_FALSE : LIT_TRUE));
      for (auto &lit : entry.first)
        printf ("%d ", lit);
      printf ("\n");

      if (entry.first.size () < shortest_l_graph_based) {
        shortest_l_graph_based = entry.first.size ();
        shortest_c_graph_based = entry.first;
      }
    }
  }
  two_bit.blocking_clauses.clear ();
  if (!shortest_c_graph_based.empty ()) {
    vector<int> clause;
    for (auto &lit : shortest_c_graph_based)
      clause.push_back (lit);
    external_clauses.push_back (clause);
    printf ("Blocking clause: ");
    print (clause);
    return true;
  }

  return false;

  // // Collect the equations and the set of vars
  // set<uint32_t> equations_vars;
  // list<Equation *> equations;
  // for (auto &level : two_bit.equations_trail)
  //   for (auto &equation : level) {
  //     equations.push_back (&equation);
  //     equations_vars.insert (equation.ids[0]);
  //     equations_vars.insert (equation.ids[1]);
  //   }

  // if (equations.empty ())
  //   return false;
  // assert (!equations_vars.empty ());

  // // Form the augmented matrix used to map the augmented matrix variable
  // IDs two_bit.aug_mtx_var_map.clear (); int id = 0; for (auto &var :
  // equations_vars)
  //   two_bit.aug_mtx_var_map[var] = id++;

  // auto confl_equations = check_consistency (equations, true);
  // bool is_consistent = confl_equations.empty ();
  // if (is_consistent)
  //   return false;

  // printf ("Equations count: %ld\n", equations.size ());
  // for (auto &equation : equations) {
  //   string ant_str;
  //   for (auto &lit : equation->antecedent)
  //     ant_str += to_string (lit) + " ";
  //   printf ("%d->%d[dir=none,color=\"%s\",label=\"%s.\"];",
  //           equation->ids[0], equation->ids[1],
  //           equation->diff == 0 ? "black" : "red", ant_str.c_str ());
  // }
  // printf ("\n");
  // printf ("Graph print:\n");
  // two_bit.graph.print ();

  // for (auto &equation : confl_equations) {
  //   cout << equation.ids[0] << (equation.diff == 0 ? " = " : "=/=")
  //        << equation.ids[1] << endl;
  // }

  // // Block inconsistencies
  // assert (external_clauses.empty ());
  // block_inconsistency (equations, two_bit.aug_mtx_var_map,
  //                      state.partial_assignment, external_clauses);
  // // Keep only the shortest clause
  // assert (!external_clauses.empty ());
  // // printf ("Blocking clauses count: %ld\n", external_clauses.size ());
  // int shortest_index = -1, shortest_length = INT_MAX;
  // for (int i = 0; i < int (external_clauses.size ()); i++) {
  //   int size = external_clauses[i].size ();
  //   if (size >= shortest_length)
  //     continue;

  //   shortest_length = size;
  //   shortest_index = i;
  // }
  // auto shortest_clause = external_clauses[shortest_index];
  // assert (!shortest_clause.empty ());
  // external_clauses.clear ();
  // external_clauses.push_back (shortest_clause);
  // for (auto &lit : shortest_clause)
  //   assert (state.partial_assignment.get (abs (lit)) ==
  //           (lit > 0 ? LIT_FALSE : LIT_TRUE));
  // printf ("Blocking clause (size %ld): ", shortest_clause.size ());
  // print (shortest_clause);

  // if (shortest_clause.size () != shortest_l_graph_based)
  //   printf ("IMPORTANT!\n");

  // return true;
}

int Propagator::cb_propagate () {
  Timer timer (&stats.total_cb_time);

#if CUSTOM_PROP
  if (propagation_lits.empty ()) {
    state.soft_refresh ();
    // if (++prop_counter % 20 == 0)
    Timer *prop_timer = new Timer (&stats.total_prop_time);
#if IS_4BIT
    custom_4bit_propagate (state, propagation_lits, reasons, stats);
#else
    custom_1bit_propagate (state, propagation_lits, reasons, stats);
#endif
    delete prop_timer;
  }
#endif

  if (propagation_lits.empty ())
    return 0;

  int &lit = propagation_lits.front ();
  assert (lit != 0);

  // If reason doesn't exist, skip propagation
  auto reason_it = reasons.find (lit);
  if (reason_it == reasons.end ()) {
    propagation_lits.pop_front ();
    return 0;
  }

  // printf ("Debug: propagate %d (var %d)\n", lit,
  //         state.var_info[abs (lit)].name);
  propagation_lits.pop_front ();
  assert (reason_it->second.antecedent.size () > 0);

  if (state.partial_assignment.get (abs (lit)) != LIT_UNDEF)
    return 0;

  return lit;
}

int Propagator::cb_add_reason_clause_lit (int propagated_lit) {
  // Timer time (&stats.total_cb_time);

  if (reason_clause.size () == 0 &&
      reasons.find (propagated_lit) == reasons.end ())
    return 0;

  if (reason_clause.size () == 0) {
    // Generate the reason clause
    auto reasons_it = reasons.find (propagated_lit);
    assert (reasons_it != reasons.end ());
    Reason reason = reasons_it->second;
    reasons.erase (reasons_it); // Consume the reason
    stats.reasons_count++;
    assert (reason.antecedent.size () > 0);

    // Populate the reason clause
    for (auto &lit : reason.antecedent) {
      // Sanity check
      assert (state.partial_assignment.get (abs (lit)) != LIT_UNDEF);
      assert (state.partial_assignment.get (abs (lit)) == LIT_TRUE
                  ? lit < 0
                  : lit > 0);
      reason_clause.push_back (lit);
    }
    reason_clause.push_back (propagated_lit);

    printf ("Reason clause: ");
    for (auto &lit : reason_clause)
      printf ("%d ", lit);
    printf ("\n");
  }

  assert (reason_clause.size () > 0);
  int lit = reason_clause.back ();
  reason_clause.pop_back ();

  return lit;
}

bool Propagator::cb_has_external_clause () {
  Timer timer (&stats.total_cb_time);

#if STRONG_PROPAGATE
  if (decision_lits.empty ()) {
    Timer *sp_timer = new Timer (&stats.total_strong_propagate_time);
#if IS_4BIT
    strong_propagate_branch_4bit (state, decision_lits, stats);
#else
    strong_propagate_branch_1bit (state, decision_lits, stats);
#endif
    delete sp_timer;
    stats.strong_prop_decisions_count += decision_lits.size ();
  }
#endif

  if (!external_clauses.empty ())
    return true;

#if CUSTOM_BLOCKING
  // if (++block_counter % 20 != 0)
  //   return false;

  // Check for 2-bit inconsistencies here
  return custom_block ();
#else
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
  auto value = state.partial_assignment.get (abs (lit));

  // Pop clause and remove if empty
  clause.pop_back ();
  if (clause.empty ()) {
    external_clauses.pop_back ();
    stats.clauses_count++;
  }

  // Sanity check for blocking clauses
  assert (lit < 0   ? value == LIT_TRUE
          : lit > 0 ? value == LIT_FALSE
                    : value != LIT_UNDEF);

  return lit;
}
