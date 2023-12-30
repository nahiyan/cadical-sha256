#ifndef _sha256_state_hpp_INCLUDED
#define _sha256_state_hpp_INCLUDED

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <stack>
#include <string>
#include <vector>

#define LIT_TRUE 2
#define LIT_FALSE 1
#define LIT_UNDEF 0
#define MAX_VAR_ID 100000

using namespace std;

namespace SHA256 {
struct Word {
  // f and g refer to the 2 blocks of SHA-256
  uint32_t ids_f[32], ids_g[32], diff_ids[32];
  // Differential characteristics
  string chars;
};
// A soft word has its characteristics defined in another word
struct SoftWord {
  // f and g refer to the 2 blocks of SHA-256
  uint32_t ids_f[32], ids_g[32], diff_ids[32];
  // Differential characteristics
  char *chars[32];
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
    SoftWord inputs[4];
    SoftWord carries[2];
  } add_w;
  struct AddT {
    SoftWord inputs[5];
    SoftWord carries[2];
  } add_t;
  struct AddE {
    SoftWord inputs[2];
    SoftWord carries[1];
  } add_e;
  struct AddA {
    SoftWord inputs[3];
    SoftWord carries[2];
  } add_a;
};

class PartialAssignment {
  uint8_t *variables;

public:
  stack<uint32_t> updated_variables;
  deque<vector<int>> *current_trail; // !Added for Debugging only

  PartialAssignment (int variables_count,
                     deque<vector<int>> *current_trail) {
    variables = new uint8_t[variables_count];
    for (int i = 0; i < MAX_VAR_ID; i++)
      variables[i] = LIT_UNDEF;
    this->current_trail = current_trail;
  }

  ~PartialAssignment () { delete[] variables; }

  void set (int lit) {
    int id = abs (lit);
    variables[id] = lit > 0 ? LIT_TRUE : LIT_FALSE;
    updated_variables.push (id);
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
    variables[id] = LIT_UNDEF;
    updated_variables.push (id);
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
  PartialAssignment partial_assignment =
      PartialAssignment (MAX_VAR_ID, &current_trail);
  Operations operations[64];
  Step steps[64 + 4];
  // Variable ID and word relations
  pair<Word *, int> id_word_rels[MAX_VAR_ID];

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