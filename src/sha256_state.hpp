#ifndef _sha256_state_hpp_INCLUDED
#define _sha256_state_hpp_INCLUDED

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <set>
#include <stack>
#include <string>
#include <vector>

#define LIT_TRUE 2
#define LIT_FALSE 1
#define LIT_UNDEF 0
#define MAX_VAR_ID 200000

using namespace std;

namespace SHA256 {
enum VariableName {
  Unknown,
  A,
  E,
  W,
  sigma0,
  sigma1,
  Sigma0,
  Sigma1,
  Maj,
  Ch,
  T,
  K,
  add_W_lc,
  add_W_hc,
  add_T_lc,
  add_T_hc,
  add_E_lc,
  add_A_lc,
  add_A_hc,
  DA,
  DE,
  DW,
  Dsigma0,
  Dsigma1,
  DSigma0,
  DSigma1,
  DMaj,
  DCh,
  DT,
  DK,
  Dadd_W_lc,
  Dadd_W_hc,
  Dadd_T_lc,
  Dadd_T_hc,
  Dadd_E_lc,
  Dadd_A_lc,
  Dadd_A_hc,
};

enum OperationId {
  op_s0,
  op_s1,
  op_sigma0,
  op_sigma1,
  op_maj,
  op_ch,
  op_add_w,
  op_add_a,
  op_add_e,
  op_add_t,
};

struct Word {
  // f and g refer to the 2 blocks of SHA-256
  uint32_t ids_f[32], ids_g[32], char_ids[32];
  // Differential characteristics
  string chars;
};
// A soft word has its characteristics defined in another word
struct SoftWord {
  // f and g refer to the 2 blocks of SHA-256
  uint32_t ids_f[32], ids_g[32], char_ids[32];
  // Differential characteristics
  char *chars[32];
};

struct VarIdentity {
  VariableName name;
  int step;
  int col;
};

struct VarInfo {
  Word *word = NULL;
  VarIdentity identity;
  bool is_fixed = false;

  // Operation ID, step, and bit position
  vector<tuple<OperationId, int, int>> operations;

  VarInfo () {}
  VarInfo (Word *word, int col, int step, VariableName name) {
    this->word = word;
    this->identity.col = col;
    this->identity.step = step;
    this->identity.name = name;
  }
};

struct Operations {
  struct S0 {
    SoftWord inputs[3];
  } s0;
  struct S1 {
    SoftWord inputs[3];
  } s1;
  struct Sigma0 {
    SoftWord inputs[3];
  } sigma0;
  struct Sigma1 {
    SoftWord inputs[3];
  } sigma1;
  // All the variable IDs stored in the following soft words are redundant
  struct Maj {
    SoftWord inputs[3];
  } maj;
  struct Ch {
    SoftWord inputs[3];
  } ch;
  struct AddW {
    SoftWord inputs[6];
    SoftWord carries[2];
  } add_w;
  struct AddT {
    SoftWord inputs[7];
    SoftWord carries[2];
  } add_t;
  struct AddE {
    SoftWord inputs[3];
    SoftWord carries[1];
  } add_e;
  struct AddA {
    SoftWord inputs[5];
    SoftWord carries[2];
  } add_a;
};

class PartialAssignment {
  uint8_t *variables;

public:
  stack<uint32_t> updated_vars;
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
    updated_vars.push (id);
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

struct Step {
  Word a, e, w, s0, s1, sigma0, sigma1, ch, maj, k, t, add_w_r[2],
      add_t_r[2], add_e_r[1], add_a_r[2];
};
class State {
public:
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
  tuple<OperationId, int, int> last_marked_op = {op_s0, -1, -1};

  void hard_refresh (bool will_propagate = false);
  void soft_refresh ();
  void refresh_char (Word &word, int &i);
  void refresh_word (Word &word);
  void print ();
  void set_operations ();
  void print_operations ();
};
} // namespace SHA256

#endif