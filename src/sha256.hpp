#include "cadical.hpp"
#include <iostream>
#include <string>

using namespace std;

namespace SHA256 {
class SHA256Propagator : CaDiCaL::ExternalPropagator {
  CaDiCaL::Solver *solver;
  static vector<string> comments;

public:
  SHA256Propagator (CaDiCaL::Solver *solver);
  ~SHA256Propagator () { this->solver->disconnect_external_propagator (); }
  void notify_assignment (int lit, bool is_fixed) {}
  void notify_new_decision_level () {}
  void notify_backtrack (size_t new_level) { (void) new_level; }
  bool cb_check_found_model (const std::vector<int> &model) {
    (void) model;
    return true;
  }
  bool cb_has_external_clause () { return false; }
  int cb_add_external_clause_lit () { return 0; }
  int cb_decide () { return 0; }
  static void add_comment_line (string line) { cout << line << endl; }
};
} // namespace SHA256