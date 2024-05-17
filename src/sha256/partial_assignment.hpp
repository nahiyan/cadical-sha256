#ifndef _sha256_partial_assignment_hpp_INCLUDED
#define _sha256_partial_assignment_hpp_INCLUDED

#include "types.hpp"
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <set>
#include <stack>
#include <string>
#include <vector>

using namespace std;

namespace SHA256 {

class PartialAssignment {
  uint8_t *variables;

public:
  std::set<uint32_t> updated_vars;
  deque<vector<int>> *current_trail; // !Debugging only
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

  inline void mark_updated_var (int id) {
    assert (id > 0);
    auto &var_info = vars_info[id];
    auto &word = var_info.word;
    if (word == NULL)
      return;

    uint32_t base_id = word->char_ids[var_info.identity.col];
    updated_vars.insert (base_id);
  }

  inline void set (int lit) {
    int id = abs (lit);
    variables[id] = lit > 0 ? LIT_TRUE : LIT_FALSE;
    mark_updated_var (id);
  }

  inline uint8_t get (int id) {
    assert (id > 0);
    return variables[id];
  }

  // !Debugging only
  // Search the entire trail for a variable
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

  inline void unset (int lit) {
    int id = abs (lit);
    if (vars_info[id].is_fixed)
      return;
    variables[id] = LIT_UNDEF;
    mark_updated_var (id);
  }
};
} // namespace SHA256

#endif