#ifndef _sha256_2_bit_hpp_INCLUDED
#define _sha256_2_bit_hpp_INCLUDED

#include "state.hpp"
#include "types.hpp"
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

vector<Equation> check_consistency (list<Equation *> &equations,
                                    bool exhaustive);
bool block_inconsistency (list<Equation *> equations,
                          map<int, int> &aug_matrix,
                          PartialAssignment &partial_assignment,
                          vector<vector<int>> &external_clauses);
vector<Equation> otf_2bit_eqs (vector<int> (*func) (vector<int> inputs),
                               string inputs, string outputs,
                               pair<vector<uint32_t>, vector<uint32_t>> ids,
                               string mask);
void load_two_bit_rules ();
} // namespace SHA256

#endif