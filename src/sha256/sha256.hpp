#ifndef _sha256_hpp_INCLUDED
#define _sha256_hpp_INCLUDED

#include "../cadical.hpp"
#include "state.hpp"
#include "types.hpp"
#include <algorithm>
#include <cassert>
#include <deque>
#include <iostream>
#include <list>
#include <map>
#include <sstream>
#include <stack>
#include <string>

using namespace std;

namespace SHA256 {
class Propagator : CaDiCaL::ExternalPropagator {
  CaDiCaL::Solver *solver;
  list<int> propagation_lits;
  vector<int> reason_clause;
  map<int, Reason> reasons;
  // Assume that the external clauses are blocking clauses
  vector<vector<int>> external_clauses;
  list<int> decision_lits;
  TwoBit two_bit;

public:
  static State state;
  static Stats stats;

  Propagator (CaDiCaL::Solver *solver);
  ~Propagator () { this->solver->disconnect_external_propagator (); }
  void notify_assignment (int lit, bool is_fixed);
  void notify_new_decision_level ();
  void notify_backtrack (size_t new_level);
  bool cb_check_found_model (const std::vector<int> &model) {
    printf ("Final state:\n");
    state.soft_refresh ();
    state.print ();
    return true;
  }
  bool cb_has_external_clause ();
  int cb_add_external_clause_lit ();
  int cb_decide ();
  int cb_propagate ();
  int cb_add_reason_clause_lit (int propagated_lit);
  static void parse_comment_line (string line, CaDiCaL::Solver *&solver);
  bool custom_block ();
};
} // namespace SHA256

#endif
