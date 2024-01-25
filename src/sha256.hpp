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
  uint reasons_count;
};

struct Differential {
  string inputs;
  string outputs;
  pair<vector<uint32_t>, vector<uint32_t>> char_base_ids;
  pair<vector<uint8_t>, vector<uint8_t>> table_values;
  vector<int> (*function) (vector<int>) = NULL;
  OperationId operation_id;
  int step_index;
  int bit_pos;
};

struct Reason {
  Differential differential;
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
  void custom_propagate ();
  void custom_branch ();
  bool custom_block ();
  void get_next_differentials (set<uint32_t> &updated_vars,
                               vector<Differential> &diffs);
};
} // namespace SHA256

#endif