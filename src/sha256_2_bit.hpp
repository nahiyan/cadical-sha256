#ifndef _sha256_2_bit_hpp_INCLUDED
#define _sha256_2_bit_hpp_INCLUDED

#include "sha256_state.hpp"
#include <list>
#include <map>
#include <unordered_map>
#include <vector>

#define TWO_BIT_XOR2_ID 0
#define TWO_BIT_IF_ID 1
#define TWO_BIT_MAJ_ID 2
#define TWO_BIT_XOR3_ID 3
#define TWO_BIT_ADD2_ID 4
#define TWO_BIT_ADD3_ID 5
#define TWO_BIT_ADD4_ID 6
#define TWO_BIT_ADD5_ID 7
#define TWO_BIT_ADD6_ID 8
#define TWO_BIT_ADD7_ID 9

using namespace std;

namespace SHA256 {

struct Equation {
  // The equations are represented by their delta IDs
  uint32_t char_ids[2];
  uint8_t diff;
  vector<uint32_t> antecedent = {};

  bool operator< (const Equation &other) const {
    if (diff != other.diff)
      return diff < other.diff;

    for (int i = 0; i < 2; i++)
      if (char_ids[i] != other.char_ids[i])
        return char_ids[i] < other.char_ids[i];

    return false; // Equal
  }
};
struct TwoBit {
  // list<Equation> equations[2];
  vector<Equation> eqs_by_op[10][64][32];
  set<Equation> eqs[2];
  map<int, int> aug_mtx_var_map;
  // TODO: Use a sorted set of pairs
  map<tuple<uint32_t, uint32_t, uint32_t>, int> bit_constraints_count;
};

void load_two_bit_rules (const char *filename);
// void derive_two_bit_equations (TwoBit &two_bit, State &state);
vector<Equation> check_consistency (set<Equation> &equations,
                                    bool exhaustive);
bool block_inconsistency (TwoBit &two_bit,
                          PartialAssignment &partial_assignment,
                          vector<vector<int>> &external_clauses,
                          int block_index = 0);
vector<Equation> otf_2bit_eqs (vector<int> (*func) (vector<int> inputs),
                               string inputs, string outputs,
                               vector<uint32_t> char_ids, string mask);
} // namespace SHA256

#endif