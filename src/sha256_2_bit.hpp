#ifndef _sha256_2_bit_hpp_INCLUDED
#define _sha256_2_bit_hpp_INCLUDED

#include "sha256.hpp"
#include <unordered_map>

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
  uint32_t ids[2];
  string names[2];
  uint8_t diff;
};

void load_two_bit_rules (const char *filename);
vector<Equation>
derive_two_bit_equations (State &state, Operations *operations, int order);
} // namespace SHA256

#endif