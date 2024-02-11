#ifndef _sha256_state_hpp_INCLUDED
#define _sha256_state_hpp_INCLUDED

#include "types.hpp"
#include <algorithm>
#include <cassert>
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

class PartialAssignment {
  uint8_t *variables;

public:
  std::set<uint32_t> updated_vars;
  deque<vector<int>> *current_trail; // !Added for Debugging only
  VarInfo *vars_info;

  PartialAssignment (int max_var_id, deque<vector<int>> *current_trail,
                     VarInfo *var_info) {
    variables = new uint8_t[max_var_id];
    for (int i = 0; i < max_var_id; i++)
      variables[i] = LIT_UNDEF;
    this->current_trail = current_trail;
    this->vars_info = var_info;
  }

  ~PartialAssignment () { delete[] variables; }

  void mark_updated_var (int id) {
    assert (id > 0);
    auto &word = vars_info[id].word;
    if (word == NULL)
      return;

    uint32_t base_id = word->char_ids[31 - vars_info[id].identity.col];
    updated_vars.insert (base_id);
  }

  void set (int lit) {
    int id = abs (lit);
    variables[id] = lit > 0 ? LIT_TRUE : LIT_FALSE;
    mark_updated_var (id);
  }

  uint8_t get (int id) {
    assert (id > 0);
    return variables[id];
  }

  // Search the entire trail for a variable (for debugging)
  uint8_t get_ (int id) {
    for (auto level_lits : *current_trail) {
      if (std::find (level_lits.begin (), level_lits.end (), id) !=
          level_lits.end ()) {
        return LIT_TRUE;
      }
      if (std::find (level_lits.begin (), level_lits.end (), -id) !=
          level_lits.end ()) {
        return LIT_FALSE;
      }
    };

    return LIT_UNDEF;
  }

  void unset (int lit) {
    int id = abs (lit);
    if (vars_info[id].is_fixed)
      return;
    variables[id] = LIT_UNDEF;
    mark_updated_var (id);
  }
};

class State {
public:
  clock_t temp_time = 0;
  deque<vector<int>> current_trail;
  int order;
  uint32_t zero_var_id;
  Word zero_word;
  Operations operations[64];
  Step steps[64 + 4];
  VarInfo vars_info[MAX_VAR_ID];
  PartialAssignment partial_assignment =
      PartialAssignment (MAX_VAR_ID, &current_trail, vars_info);

  // Operation ID, step index, bit position
  bool marked_operations[10][64][32];
  bool marked_operations_strong_prop[10][64];

  // TODO: Try doing propagation for every single marked operation
  tuple<OperationId, int, int> last_marked_op = {op_s0, -1, -1};

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