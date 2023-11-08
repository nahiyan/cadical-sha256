#ifndef _sha256_hpp_INCLUDED
#define _sha256_hpp_INCLUDED

#include "cadical.hpp"
#include <algorithm>
#include <deque>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

#define ABS_STEP(i) (i + 4)
#define LIT_TRUE 2
#define LIT_FALSE 1
#define LIT_UNDEF 0

inline bool has_prefix (std::string pre, std::string str) {
  return str.compare (0, pre.size (), pre) == false;
}

using namespace std;

inline std::string trim (std::string &str) {
  str.erase (str.find_last_not_of (' ') + 1); // suffixing spaces
  str.erase (0, str.find_first_not_of (' ')); // prefixing spaces
  return str;
}

namespace SHA256 {
struct Word {
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

class PartialAssignment {
  // TODO: Construct with size of max(observed_vars) in the heap
  uint8_t variables[100000];

public:
  void set (int lit) {
    int id = abs (lit);
    variables[id] = lit > 0 ? LIT_TRUE : LIT_FALSE;
  }
  uint8_t get (int id) { return variables[id]; }
  void unset (int lit) {
    int id = abs (lit);
    variables[id] = LIT_UNDEF;
  }
};

class Propagator : CaDiCaL::ExternalPropagator {
  CaDiCaL::Solver *solver;
  // TODO: Use more efficient data structure
  deque<std::vector<int>> current_trail;
  static int order;
  static State state;
  static Operations operations[64];
  PartialAssignment partial_assignment;
  static void set_operations ();
  void print_state ();
  void refresh_state ();
  void prop_addition_weakly ();

  vector<int> propagation_lits;
  map<int, vector<int>> reason_clauses;

public:
  Propagator (CaDiCaL::Solver *solver);
  ~Propagator () { this->solver->disconnect_external_propagator (); }
  void notify_assignment (int lit, bool is_fixed);
  void notify_new_decision_level ();
  void notify_backtrack (size_t new_level);
  bool cb_check_found_model (const std::vector<int> &model) {
    (void) model;
    return true;
  }
  bool cb_has_external_clause () { return false; }
  int cb_add_external_clause_lit () { return 0; }
  int cb_decide () { return 0; }
  int cb_propagate ();
  int cb_add_reason_clause_lit (int propagated_lit);
  static void parse_comment_line (string line, CaDiCaL::Solver *&solver);
};
} // namespace SHA256

#endif