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
  Word a, e, w, s0, s1, sigma0, sigma1, ch, maj;
};

struct State {
  Step steps[64 + 4];
};

class PartialAssignment {
  uint8_t variables[50000];

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
  std::deque<std::vector<int>> current_trail;
  static int order;
  static State state;
  PartialAssignment partial_assignment;
  void print_state ();
  void refresh_state ();
  static void add_observed_vars (Word *word, CaDiCaL::Solver *&solver);

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
  static void parse_comment_line (string line, CaDiCaL::Solver *&solver);
};
} // namespace SHA256

#endif