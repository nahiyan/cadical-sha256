#ifndef _sha256_state_hpp_INCLUDED
#define _sha256_state_hpp_INCLUDED

#include "partial_assignment.hpp"
#include "types.hpp"
#include <algorithm>
#include <cassert>
#include <climits>
#include <cmath>
#include <cstdint>
#include <set>
#include <stack>
#include <string>
#include <vector>

// TODO: Make it dynamic
#define MAX_VAR_ID 200000

using namespace std;

namespace SHA256 {
class State {
public:
  clock_t total_refresh_time = 0;
  deque<vector<int>> current_trail;
  int order;
#if !IS_LI2024
  uint32_t zero_var_id;
  Word zero_word;
#else
  int start_step = INT_MAX, end_step = 0;
#endif
  Operations operations[64];
  Step steps[64 + 4];
  VarInfo vars_info[MAX_VAR_ID];
  PartialAssignment partial_assignment =
      PartialAssignment (MAX_VAR_ID, &current_trail, vars_info);

  // Operation ID, step index, bit position
  bool marked_operations_wordwise_prop[NUM_OPS][64];
  list<list<Marking>> prop_markings_trail;
  list<list<Marking>> two_bit_markings_trail;

  void hard_refresh (bool will_propagate = false);
  void soft_refresh ();
  void refresh_char (Word &word, int i);
  void refresh_word (Word &word);
  void print ();
  void set_operations ();
  void print_operations ();
};
} // namespace SHA256

#endif