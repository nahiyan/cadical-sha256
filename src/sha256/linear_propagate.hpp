#ifndef _sha256__linear_propagate_hpp_INCLUDED
#define _sha256__linear_propagate_hpp_INCLUDED

#include "NTL/mat_GF2.h"
#include "NTL/vec_GF2.h"
#include <cassert>
#include <string>

using namespace std;

namespace SHA256 {
// Takes the base matrix (pre-computed with equations of the operation)
// along with the differential to perform linear propagation
inline pair<string, string>
linear_propagate (NTL::mat_GF2 mat_A, string inputs, string outputs) {
  pair<string, string> output;

  NTL::vec_GF2 vec_b;
  vec_b.SetLength (mat_A.NumCols ());
  auto inputs_size = inputs.size ();
  auto outputs_size = outputs.size ();

  assert (mat_A.NumCols () % 2 == 0);
  assert (mat_A.NumCols () == mat_A.NumRows ());
  assert (size_t (mat_A.NumCols ()) == 2 * (inputs_size + outputs_size));

  for (int i = 0; i < mat_A.NumCols () / 2; i++)
    vec_b[i] = 0;

  for (int i = 0; i < mat_A.NumRows (); ++i) {
    for (int j = 0; j < mat_A.NumCols (); ++j) {
      cout << mat_A[i][j] << " ";
    }
    cout << endl;
  }

  size_t row_offset = outputs.size () * 2;
  // Express the characteristics as linear equations
  for (int x = 0; x < inputs_size; x++) {
    assert (inputs[x] == '?' || inputs[x] == '-' || inputs[x] == 'x' ||
            inputs[x] == 'n' || inputs[x] == 'u' || inputs[x] == '1' ||
            inputs[x] == '0');
    if (inputs[x] == '?')
      continue;
  }

  return output;
}
} // namespace SHA256

#endif