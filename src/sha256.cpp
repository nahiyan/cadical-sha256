#include "sha256.hpp"
#include <cstdlib>

using namespace SHA256;
using namespace std;

SHA256Propagator::SHA256Propagator (CaDiCaL::Solver *solver) {
  this->solver = solver;
  this->solver->connect_external_propagator (this);
  printf ("Connected!");
}