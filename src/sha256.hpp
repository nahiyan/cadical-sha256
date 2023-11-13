#ifndef _sha256_hpp_INCLUDED
#define _sha256_hpp_INCLUDED

#include "cadical.hpp"
#include <algorithm>
#include <cassert>
#include <deque>
#include <iostream>
#include <list>
#include <map>
#include <sstream>
#include <string>

#define ABS_STEP(i) (i + 4)
#define LIT_TRUE 2
#define LIT_FALSE 1
#define LIT_UNDEF 0

using namespace std;

namespace SHA256 {
struct Word {
  // TODO: Rename "diff_ids" to delta_ids
  // f and g refer to the 2 blocks of SHA-256
  uint32_t ids_f[32], ids_g[32], diff_ids[32];
  // Differential characteristics
  string chars;
};

struct Step {
  Word a, e, w, s0, s1, sigma0, sigma1, ch, maj, k, t, add_w_r[2],
      add_t_r[2], add_e_r[1], add_a_r[2];
};

struct State {
  Step steps[64 + 4];
};

struct Operations {
  struct S0 {
    Word inputs[3];
  } s0;
  struct S1 {
    Word inputs[3];
  } s1;
  struct Sigma0 {
    Word inputs[3];
  } sigma0;
  struct Sigma1 {
    Word inputs[3];
  } sigma1;
  struct Maj {
    Word inputs[3];
  } maj;
  struct Ch {
    Word inputs[3];
  } ch;
  struct AddW {
    Word *inputs[4];
    Word *carries[2];
  } add_w;
  struct AddT {
    Word *inputs[5];
    Word *carries[2];
  } add_t;
  struct AddE {
    Word *inputs[2];
    Word *carries[1];
  } add_e;
  struct AddA {
    Word *inputs[3];
    Word *carries[2];
  } add_a;
};

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

class PartialAssignment {
  // TODO: Construct with size of max(observed_vars) in the heap
  uint8_t variables[100000];

public:
  PartialAssignment () {
    for (int i = 0; i < 100000; i++)
      variables[i] = LIT_UNDEF;
  }

  void set (int lit) {
    int id = abs (lit);
    variables[id] = lit > 0 ? LIT_TRUE : LIT_FALSE;
  }
  uint8_t get (int id) {
    // printf ("Debug: get %d\n", id);
    assert (id > 0);
    return variables[id];
  }
  void unset (int lit) {
    int id = abs (lit);
    variables[id] = LIT_UNDEF;
  }
};

struct TwoBit {
  vector<Equation> equations[2];
  map<int, int> aug_mtx_var_map;
  // IDs that contributed to the equation
  map<Equation, vector<int>> equation_ids_map;
  map<tuple<uint32_t, uint32_t, uint32_t>, int> bit_constraints_count;
};

struct Stats {
  clock_t total_cb_time;
};

class Propagator : CaDiCaL::ExternalPropagator {
  CaDiCaL::Solver *solver;
  // TODO: Use more efficient data structure
  deque<std::vector<int>> current_trail;
  static int order;
  static State state;
  static Operations operations[64];
  PartialAssignment partial_assignment;
  vector<Equation> two_bit_eqs;
  vector<int> propagation_lits;
  map<int, vector<int>> reason_clauses;
  // Assume that the external clauses are blocking clauses
  vector<vector<int>> external_clauses;
  list<int> decision_lits;
  TwoBit two_bit;

  static void set_operations ();
  void print_state ();
  void refresh_state ();
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
    refresh_state ();
    printf ("Final state:\n");
    print_state ();
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