#ifndef _sha256_util_hpp_INCLUDED
#define _sha256_util_hpp_INCLUDED

#include <string>

using namespace std;

namespace SHA256 {
string rotate_word (char *word, int amount, bool is_circular = true);
int64_t e_mod (int64_t a, int64_t b);
} // namespace SHA256

#endif