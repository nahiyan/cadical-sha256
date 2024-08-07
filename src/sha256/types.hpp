#ifndef _sha256_types_hpp_INCLUDED
#define _sha256_types_hpp_INCLUDED

#include "2_bit_graph.hpp"
#include <cinttypes>
#include <cstdint>
#include <list>
#include <map>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

#define ABS_STEP(i) (i + 4)

// Select the encoding type
#define IS_1BIT false   // 1-bit variant of nejati-collision encoding
#define IS_LI2024 false // Li et al. FSE 2024 encoding
#define IS_4BIT false   // 4-bit variant of nejati-collision encoding

// Select the propagation techniques
#define CUSTOM_PROP false         // Bitsliced propagation
#define WORDWISE_PROPAGATE false  // Wordwise propagation
#define CUSTOM_BLOCKING false     // Inconsistency blocking
#define TWO_BIT_ADD_DIFFS false   // Inconsistency blocking with addition
#define MENDEL_BRANCHING false    // Mendel et al.'s branching
#define MENDEL_BRANCHING_STAGES 3 // Stages in Mendel et al.'s branching

#define SET_PHASE false          // Set phase to false for primary variables
#define SHOW_DECISION_DIST false // Show the decision distribution

#define PRINT_BP_REASON_CLAUSE false // Print the bitsliced reason clauses
#define PRINT_WP_REASON_CLAUSE false // Print the wordwise reason clauses
#define PRINT_BLOCKING_CLAUSE \
  false // Print the inconsistency blocking clauses

#if IS_LI2024
#define NUM_OPS 9
#else
#define NUM_OPS 10
#endif

#define LIT_TRUE 2
#define LIT_FALSE 1
#define LIT_UNDEF 0

using namespace std;

namespace SHA256 {
enum FunctionId { ch, maj, xor3, add };
// TODO: Integrate this
enum AdditionId { add_a, add_e, add_w, add_t };

enum VariableName {
#if !IS_LI2024
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
#else
  Unknown,
  A,
  E,
  W,
  B0,
  B1,
  B2,
  B3,
  B4,
  B5,
  B6,
  B7,
  B8,
  B9,
  C0,
  C1,
  C2,
  C3,
  C4,
  C5,
  C6,
  C7,
  MB0,
  MB2,
#endif
};

enum OperationId {
#if IS_1BIT || IS_4BIT
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
#elif IS_LI2024
  op_s0,
  op_s1,
  op_sigma0,
  op_sigma1,
  op_maj,
  op_ch,
  op_add_w,
  op_add_a,
  op_add_e,
// op_add_b2,
// op_add_b3,
// op_add_b5,
// op_add_b4,
#endif
};

struct Word {
#if !IS_LI2024
  // f and g refer to the 2 blocks of SHA-256
  uint32_t ids_f[32], ids_g[32], char_ids[32];
#else
  uint32_t char_ids[2][33];
#endif
  // Differential characteristics
  string chars;
};
// A soft word has its characteristics defined in another word
struct SoftWord {
#if !IS_LI2024
  // f and g refer to the 2 blocks of SHA-256
  uint32_t ids_f[32], ids_g[32], char_ids[32];
#else
  uint32_t char_ids[2][32];
#endif
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
  // Total callback time
  clock_t total_cb_time = 0;
  // Time for bitwise propagation
  clock_t total_prop_time = 0;
  // Time for wordwise propagation
  clock_t total_ww_propagate_time = 0;
  // Time for 2-bit equation derivation
  clock_t total_two_bit_derive_time = 0;
  clock_t total_mendel_branch_time = 0;

  uint64_t clauses_count = 0;
  uint64_t reasons_count = 0;
  uint64_t decisions_count = 0;
  uint64_t wordwise_prop_decisions_count = 0;
  // Decisions made with mendel's branching technique
  uint64_t mendel_branching_decisions_count = 0;
  uint64_t mendel_branching_stage3_count = 0;

  // Branching stats for primary variables
  pair<uint64_t, uint64_t> dw_count = {0, 0};
  pair<uint64_t, uint64_t> de_count = {0, 0};
  pair<uint64_t, uint64_t> da_count = {0, 0};
  pair<uint64_t, uint64_t> a_count = {0, 0};
  pair<uint64_t, uint64_t> e_count = {0, 0};
  pair<uint64_t, uint64_t> w_count = {0, 0};

  vector<uint64_t> decisions_dist_da = vector<uint64_t> (10000, 0);
  vector<uint64_t> decisions_dist_de = vector<uint64_t> (10000, 0);
  vector<uint64_t> decisions_dist_dw = vector<uint64_t> (10000, 0);
  vector<uint64_t> decisions_dist_a = vector<uint64_t> (10000, 0);
  vector<uint64_t> decisions_dist_e = vector<uint64_t> (10000, 0);
  vector<uint64_t> decisions_dist_w = vector<uint64_t> (10000, 0);

  // Cache stats
  uint64_t prop_total_calls = 0;
  uint64_t prop_cached_calls = 0;
  uint64_t two_bit_total_calls = 0;
  uint64_t two_bit_cached_calls = 0;
};

struct Operations {
#if !IS_LI2024
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

  SoftWord *inputs_by_op_id[NUM_OPS];
  Word **outputs_by_op_id[NUM_OPS];
#else
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
  struct AddE {
    SoftWord inputs[8];
    Word *outputs[3];
  } add_e;
  struct AddA {
    SoftWord inputs[6];
    Word *outputs[3];
  } add_a;
  // struct AddB2 {
  //   SoftWord inputs[3];
  //   SoftWord outputs[2];
  // } add_b2;
  // struct AddB3 {
  //   SoftWord inputs[3];
  //   SoftWord outputs[2];
  // } add_b3;
  // struct AddB4 {
  //   SoftWord inputs[3];
  //   SoftWord outputs[2];
  // } add_b4;
  // struct AddB5 {
  //   SoftWord inputs[3];
  //   SoftWord outputs[2];
  // } add_b5;
  SoftWord *inputs_by_op_id[NUM_OPS];
  Word **outputs_by_op_id[NUM_OPS];
#endif
};

struct Reason {
  vector<int> antecedent;
  pair<string, string> differentials;
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

  // * Graph approach
  TwoBitGraph graph;
  list<pair<unordered_set<int>, int>> blocking_clauses;
};

struct Step {
#if IS_LI2024
  Word a, e, w, b[10], c[8], mb[5];
#else
  Word a, e, w, s0, s1, sigma0, sigma1, ch, maj, k, t, add_w_r[2],
      add_t_r[2], add_e_r[1], add_a_r[2];
#endif
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
