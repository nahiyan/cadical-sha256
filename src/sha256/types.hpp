#ifndef _sha256_types_hpp_INCLUDED
#define _sha256_types_hpp_INCLUDED

#include <cinttypes>
#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#define LIT_TRUE 2
#define LIT_FALSE 1
#define LIT_UNDEF 0

using namespace std;

namespace SHA256 {
enum FunctionId { ch, maj, xor3, add };
// TODO: Integrate this
enum AdditionId { add_a, add_e, add_w, add_t };

enum VariableName {
  Unknown,
  Zero,
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
  VarInfo (Word *word, int step, int col, VariableName name) {
    this->word = word;
    this->identity.step = step;
    this->identity.col = col;
    this->identity.name = name;
  }
};

struct Stats {
  clock_t total_cb_time = 0;
  // Time for differential propagation
  clock_t total_prop_time = 0;
  // Time for 2-bit equation derivation
  clock_t total_two_bit_derive_time = 0;
  clock_t total_two_bit_check_time = 0;
  clock_t total_mendel_branch_time = 0;
  clock_t total_strong_propagate_time = 0;
  uint64_t clauses_count = 0;
  uint64_t reasons_count = 0;
  uint64_t decisions_count = 0;
  uint64_t strong_prop_decisions_count = 0;
  // Decisions made with mendel's branching technique
  uint64_t mendel_branching_decisions_count = 0;
  uint64_t mendel_branching_stage3_count = 0;

  // Cache
  uint64_t prop_total_calls = 0;
  uint64_t prop_cached_calls = 0;
  uint64_t two_bit_total_calls = 0;
  uint64_t two_bit_cached_calls = 0;
};

struct Operations {
  struct S0 {
    SoftWord inputs[3];
    Word *outputs[1];
  } s0;
  struct S1 {
    SoftWord inputs[3];
    Word *outputs[1];
  } s1;
  struct Sigma0 {
    SoftWord inputs[3];
    Word *outputs[1];
  } sigma0;
  struct Sigma1 {
    SoftWord inputs[3];
    Word *outputs[1];
  } sigma1;
  // All the variable IDs stored in the following soft words are redundant
  struct Maj {
    SoftWord inputs[3];
    Word *outputs[1];
  } maj;
  struct Ch {
    SoftWord inputs[3];
    Word *outputs[1];
  } ch;
  struct AddW {
    SoftWord inputs[6];
    Word *outputs[3];
  } add_w;
  struct AddT {
    SoftWord inputs[7];
    Word *outputs[3];
  } add_t;
  struct AddE {
    SoftWord inputs[3];
    Word *outputs[3];
  } add_e;
  struct AddA {
    SoftWord inputs[5];
    Word *outputs[3];
  } add_a;

  SoftWord *inputs_by_op_id[10];
  Word **outputs_by_op_id[10];
};

struct Reason {
  vector<int> antecedent;
};

struct Equation {
  // The equations are represented by their delta IDs
  uint32_t ids[2];
  uint8_t diff;
  vector<int> antecedent = {};

  bool operator< (const Equation &other) const {
    if (diff != other.diff)
      return diff < other.diff;

    for (int i = 0; i < 2; i++)
      if (ids[i] != other.ids[i])
        return ids[i] < other.ids[i];

    return false; // Equal
  }
};

struct TwoBit {
  list<list<Equation>> equations_trail;
  // set<Equation> equations;
  // vector<Equation> eqs_by_op[10][64][32];
  map<int, int> aug_mtx_var_map;
  // TODO: Use a sorted set of pairs
  map<uint64_t, int> eq_freq;
};

struct Step {
  Word a, e, w, s0, s1, sigma0, sigma1, ch, maj, k, t, add_w_r[2],
      add_t_r[2], add_e_r[1], add_a_r[2];
};

struct Marking {
  OperationId op_id;
  int step_i;
  int bit_pos;
  // The variable that led to this marking
  uint32_t basis;
};

} // namespace SHA256

#endif