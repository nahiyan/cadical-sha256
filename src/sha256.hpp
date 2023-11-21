#ifndef _sha256_hpp_INCLUDED
#define _sha256_hpp_INCLUDED

#include "cadical.hpp"
#include "sha256_state.hpp"
#include <algorithm>
#include <cassert>
#include <deque>
#include <iostream>
#include <list>
#include <map>
#include <sstream>
#include <stack>
#include <string>

#define ABS_STEP(i) (i + 4)

using namespace std;

namespace SHA256 {
struct Equation {
  // The equations are represented by their delta IDs
  uint32_t diff_ids[2];
  string names[2];
  uint8_t diff;

  bool operator< (const Equation &other) const {
    if (diff != other.diff)
      return diff < other.diff;

    for (int i = 0; i < 2; i++)
      if (diff_ids[i] != other.diff_ids[i])
        return diff_ids[i] < other.diff_ids[i];

    return false; // Equal
  }
};
struct TwoBit {
  vector<Equation> equations[2];
  map<int, int> aug_mtx_var_map;
  // Equations and the IDs that contributed to it
  map<Equation, vector<int>> equation_vars_map;
  // TODO: Use a sorted set of pairs
  map<tuple<uint32_t, uint32_t, uint32_t>, int> bit_constraints_count;
};

struct Stats {
  clock_t total_cb_time;
  uint clauses_count;
  uint decisions_count;
};

class Propagator : CaDiCaL::ExternalPropagator {
  CaDiCaL::Solver *solver;
  // TODO: Use more efficient data structure
  deque<std::vector<int>> current_trail;
  static int order;
  static State state;
  vector<Equation> two_bit_eqs;
  vector<int> propagation_lits;
  map<int, vector<int>> reason_clauses;
  // Assume that the external clauses are blocking clauses
  vector<vector<int>> external_clauses;
  list<int> decision_lits;
  TwoBit two_bit;

  void prop_addition_weakly ();

public:
  static Stats stats;

  Propagator (CaDiCaL::Solver *solver);
  ~Propagator () { this->solver->disconnect_external_propagator (); }
  void notify_assignment (int lit, bool is_fixed);
  void notify_new_decision_level ();
  void notify_backtrack (size_t new_level);
  bool cb_check_found_model (const std::vector<int> &model) {
    (void) model;
    state.hard_refresh ();
    printf ("Final state:\n");
    state.print ();
    return true;
  }
  bool cb_has_external_clause ();
  int cb_add_external_clause_lit ();
  int cb_decide ();
  int cb_propagate ();
  int cb_add_reason_clause_lit (int propagated_lit);
  static void parse_comment_line (string line, CaDiCaL::Solver *&solver);
};
} // namespace SHA256

#endif