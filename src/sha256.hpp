#ifndef _sha256_hpp_INCLUDED
#define _sha256_hpp_INCLUDED

#include "cadical.hpp"
#include "sha256_2_bit.hpp"
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
struct Stats {
  clock_t total_cb_time;
  uint clauses_count;
  uint decisions_count;
};

struct Reason {
  pair<string, string> differential;
  vector<vector<int>> input_ids, output_ids;
  vector<int> antecedent;
};

class Propagator : CaDiCaL::ExternalPropagator {
  CaDiCaL::Solver *solver;
  static int order;
  static State state;
  vector<Equation> two_bit_eqs;
  vector<int> propagation_lits;
  vector<int> reason_clause;
  map<int, Reason> reasons;
  // Assume that the external clauses are blocking clauses
  vector<vector<int>> external_clauses;
  list<int> decision_lits;
  TwoBit two_bit;

  unordered_map<char, vector<int>> gc_table = {
      {'?', {1, 1, 1, 1}}, {'-', {1, 0, 0, 1}}, {'x', {0, 1, 1, 0}},
      {'0', {1, 0, 0, 0}}, {'u', {0, 1, 0, 0}}, {'n', {0, 0, 1, 0}},
      {'1', {0, 0, 0, 1}}, {'3', {1, 1, 0, 0}}, {'5', {1, 0, 1, 0}},
      {'7', {1, 1, 1, 0}}, {'A', {0, 1, 0, 1}}, {'B', {1, 1, 0, 1}},
      {'C', {0, 0, 1, 1}}, {'D', {1, 0, 1, 1}}, {'E', {0, 1, 1, 1}}};

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
  void custom_branch ();
  void propagate_operations ();
};
} // namespace SHA256

#endif