#include "sha256.hpp"
#include <cstdlib>

using namespace SHA256;
using namespace std;

int Propagator::order = 0;

Propagator::Propagator (CaDiCaL::Solver *solver) {
  this->solver = solver;
  solver->connect_external_propagator (this);
  printf ("Connected!\n");
  current_trail.push_back (std::vector<int> ());
  solver->add_observed_var (1);
}

void Propagator::parse_comment_line (string line) {
  std::istringstream iss (line);
  string key;
  int value;
  iss >> key >> value;

  // Determine the order
  if (is_prefix ("DW", key))
    Propagator::order =
        max (std::stoi (key.substr (3)) + 1, Propagator::order);

  // cout << key << " " << value << endl;
}

void Propagator::notify_assignment (int lit, bool is_fixed) {
  if (is_fixed)
    current_trail.front ().push_back (lit);
  else
    current_trail.back ().push_back (lit);

  // Assign variables in the partial assignment
  partial_assignment.set (lit);

  printf ("Debug: %d %d %d %d\n", lit, is_fixed, partial_assignment.get (1),
          partial_assignment.get (2));
}

void Propagator::notify_backtrack (size_t new_level) {
  while (current_trail.size () > new_level + 1) {
    // Unassign the variables that are removed from the trail
    for (auto lit : current_trail.back ()) {
      partial_assignment.unset (lit);
    }
    current_trail.pop_back ();
  }
}

void Propagator::notify_new_decision_level () {
  current_trail.push_back (std::vector<int> ());
}
