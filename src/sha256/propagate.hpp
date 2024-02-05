#ifndef _sha256_propagate_hpp_INCLUDED
#define _sha256_propagate_hpp_INCLUDED

#include <cstdint>
#include <string>
#include <vector>

using namespace std;

namespace SHA256 {
string otf_propagate (vector<int> (*func) (vector<int> inputs),
                      string inputs, string outputs);
} // namespace SHA256

#endif