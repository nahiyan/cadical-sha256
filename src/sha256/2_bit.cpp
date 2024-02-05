#include "lru_cache.hpp"
#include "propagate.hpp"
#include "state.hpp"
#include "util.hpp"

#include "NTL/GF2.h"
#include "NTL/mat_GF2.h"
#include "NTL/vec_GF2.h"
#include <cassert>
#include <climits>
#include <fstream>
#include <memory>
#include <set>
#include <sstream>

namespace SHA256 {
unordered_map<string, string> two_bit_rules;

// Checks GF(2) equations and returns conflicting equations (equations that
// conflicts with previously added ones)
vector<Equation> check_consistency (set<Equation> &equations,
                                    bool exhaustive) {
  vector<Equation> conflicting_equations;
  map<uint32_t, shared_ptr<set<int32_t>>> rels;

  for (auto &equation : equations) {
    int lit1 = equation.char_ids[0];
    int lit2 = (equation.diff == 1 ? -1 : 1) * (equation.char_ids[1]);
    auto var1 = abs (int (lit1));
    auto var2 = abs (int (lit2));
    auto var1_exists = rels.find (var1) == rels.end () ? false : true;
    auto var2_exists = rels.find (var2) == rels.end () ? false : true;

    if (var1_exists && var2_exists) {
      auto var1_inv_exists =
          rels[var1]->find (-lit1) == rels[var1]->end () ? false : true;
      auto var2_inv_exists =
          rels[var2]->find (-lit2) == rels[var2]->end () ? false : true;

      // Ignore if both inverses are found (would be a redudant operation)
      if (var1_inv_exists && var2_inv_exists)
        continue;

      // Try to prevent conflict by inverting one set
      bool invert = false;
      if (var2_inv_exists || var1_inv_exists)
        invert = true;

      // Union the sets
      for (auto item : *rels[var2])
        rels[var1]->insert ((invert ? -1 : 1) * item);

      auto &updated_set = rels[var1];
      // If both a var and its inverse is present in the newly updated set,
      // it's a contradiction
      {
        auto var1_inv_exists =
            updated_set->find (-var1) == updated_set->end () ? false : true;
        auto var2_inv_exists =
            updated_set->find (-var2) == updated_set->end () ? false : true;
        auto var1_exists =
            updated_set->find (var1) == updated_set->end () ? false : true;
        auto var2_exists =
            updated_set->find (var2) == updated_set->end () ? false : true;

        if ((var1_inv_exists && var1_exists) ||
            (var2_inv_exists && var2_exists)) {
          Equation confl_eq;
          confl_eq.char_ids[0] = var1;
          confl_eq.char_ids[1] = var2;
          confl_eq.diff = lit2 < 0 ? 1 : 0;
          conflicting_equations.push_back (confl_eq);
          if (!exhaustive)
            return conflicting_equations;
        }
      }

      // Update existing references
      for (auto &item : *updated_set) {
        auto &set = rels[abs (item)];
        if (set == updated_set)
          continue;
        rels[abs (item)] = updated_set;
      }
    } else if (var1_exists || var2_exists) {
      // Find an existing set related to any of the variables
      auto &existing_set = var1_exists ? rels[var1] : rels[var2];
      auto var1_inv_in_existing_set =
          existing_set->find (-lit1) == existing_set->end () ? false : true;
      auto var2_inv_in_existing_set =
          existing_set->find (-lit2) == existing_set->end () ? false : true;

      // Invert the lone variable to try to prevent a conflict
      if (var1_inv_in_existing_set)
        lit2 *= -1;
      else if (var2_inv_in_existing_set)
        lit1 *= -1;

      // Add the var to an existing set
      if (var1_exists)
        rels[var1]->insert (lit2);
      else
        rels[var2]->insert (lit1);

      // Update existing references
      for (auto &item : *existing_set) {
        auto &set = rels[abs (item)];
        if (set == existing_set)
          continue;
        rels[abs (item)] = existing_set;
      }
    } else {
      // Adding novel variables
      auto new_set = make_shared<set<int>> (set<int>{lit1, lit2});
      rels[var1] = new_set;
      rels[var2] = new_set;
    }
  }

  return conflicting_equations;
}

// Create the augmented matrix from equations
void make_aug_matrix (TwoBit &two_bit, NTL::mat_GF2 &coeff_matrix,
                      NTL::vec_GF2 &rhs, int block_index) {
  int variables_n = two_bit.aug_mtx_var_map.size ();
  int equations_n = two_bit.eqs[block_index].size ();
  coeff_matrix.SetDims (equations_n, variables_n);
  rhs.SetLength (equations_n);

  // Construct the coefficient matrix
  auto &equations = two_bit.eqs[block_index];
  int eq_index = 0;
  for (auto &equation : equations) {
    int &x = two_bit.aug_mtx_var_map[equation.char_ids[0]];
    int &y = two_bit.aug_mtx_var_map[equation.char_ids[1]];
    for (int col_index = 0; col_index < variables_n; col_index++)
      coeff_matrix[eq_index][col_index] =
          NTL::to_GF2 (col_index == x || col_index == y ? 1 : 0);

    rhs.put (eq_index, equation.diff);
    eq_index++;
  }
}

// Detect inconsistencies from nullspace vectors
int find_inconsistency_from_nullspace_vectors (
    TwoBit &two_bit, NTL::mat_GF2 &coeff_matrix, NTL::vec_GF2 &rhs,
    NTL::mat_GF2 &nullspace_vectors, NTL::vec_GF2 *&inconsistency,
    int block_index) {
  int coeff_n = coeff_matrix.NumCols ();
  int inconsistent_eq_n = 0;
  int least_hamming_weight = INT_MAX;
  int nullspace_vectors_n = nullspace_vectors.NumRows ();
  int equations_n = two_bit.eqs[block_index].size ();
  for (int index = 0; index < nullspace_vectors_n; index++) {
    auto &nullspace_vector = nullspace_vectors[index];

    // Initialize the values to 0
    NTL::GF2 rhs_sum = NTL::to_GF2 (0);
    NTL::vec_GF2 coeff_sums;
    coeff_sums.SetLength (coeff_n);
    for (int x = 0; x < coeff_n; x++)
      coeff_sums[x] = 0;

    // Go through the nullspace vector and add the equations and RHS
    for (int eq_index = 0; eq_index < equations_n; eq_index++) {
      if (nullspace_vector[eq_index] == 0)
        continue;

      // Add the coefficients of the equations
      coeff_sums += coeff_matrix[eq_index];

      // Add the RHS
      rhs_sum += rhs[eq_index];
    }

    // Mismatching RHS sum and coefficients sum is a contradiction
    if (rhs_sum != sum (coeff_sums)) {
      int hamming_weight = 0;
      for (int x = 0; x < equations_n; x++)
        hamming_weight += NTL::conv<int> (nullspace_vector[x]);

      if (hamming_weight < least_hamming_weight) {
        inconsistency = &nullspace_vector;
      }
      inconsistent_eq_n++;
    }
  }

  return inconsistent_eq_n;
}

// Use NTL to find cycles of inconsistent equations
bool block_inconsistency (TwoBit &two_bit,
                          PartialAssignment &partial_assignment,
                          vector<vector<int>> &external_clauses,
                          int block_index) {
  // Make the augmented matrix
  NTL::mat_GF2 coeff_matrix;
  NTL::vec_GF2 rhs;
  make_aug_matrix (two_bit, coeff_matrix, rhs, block_index);

  // Find the basis of the coefficient matrix's left kernel
  NTL::mat_GF2 left_kernel_basis;
  NTL::kernel (left_kernel_basis, coeff_matrix);
  auto equations_n = left_kernel_basis.NumCols ();

  // TODO: Add combinations of the basis vectors

  // Check for inconsistencies
  NTL::vec_GF2 *inconsistency = NULL;
  auto inconsistent_eq_n = find_inconsistency_from_nullspace_vectors (
      two_bit, coeff_matrix, rhs, left_kernel_basis, inconsistency,
      block_index);
  if (inconsistency == NULL)
    return false;

  // Blocking inconsistencies
  auto &inconsistency_deref = *inconsistency;

  // Store lits in a set to avoid duplicates
  set<int> clause_lits;
  int eq_index = 0;
  for (auto &equation : two_bit.eqs[block_index]) {
    if (inconsistency_deref[eq_index++] == 0)
      continue;

    auto &antecedent = equation.antecedent;
    assert (!antecedent.empty ());
    for (auto &lit : antecedent) {
      auto value = partial_assignment.get (abs ((int) lit));
      assert (value == (lit > 0 ? LIT_FALSE : LIT_TRUE));
      clause_lits.insert (lit);
    }
  }
  assert (!clause_lits.empty ());

  // Push the blocking/conflict clause
  vector<int> clause;
  for (auto &lit : clause_lits)
    clause.push_back (lit);
  assert (!clause.empty ());
  external_clauses.push_back (clause);

  return true;
}

cache::lru_cache<string, vector<set<int>>> otf_2bit_cache (350e3);
vector<Equation> otf_2bit_eqs (vector<int> (*func) (vector<int> inputs),
                               string inputs, string outputs,
                               vector<uint32_t> char_ids, string mask) {
  vector<Equation> equations;
  vector<set<int>> diff_pairs;
  // printf ("%ld %ld %ld\n", inputs.size (), outputs.size (),
  //         char_ids.size ());
  assert (inputs.size () + outputs.size () == char_ids.size ());
  assert (char_ids.size () == mask.size ());

  FunctionId func_id = func == add_   ? add
                       : func == xor_ ? xor3
                       : func == maj_ ? maj
                                      : ch;

  // Look in the cache
  bool is_cached = false;
  string cache_key;
  {
    stringstream ss;
    ss << func_id << " " << inputs << " " << outputs;
    cache_key = ss.str ();
  }
  if (otf_2bit_cache.exists (cache_key)) {
    is_cached = true;
    diff_pairs = otf_2bit_cache.get (cache_key);
  }

  auto all_chars = inputs + outputs;
  assert (all_chars.size () == inputs.size () + outputs.size ());

  if (!is_cached) {
    vector<int> positions;
    for (int i = 0; i < int (all_chars.size ()); i++)
      if (is_in (all_chars[i], {'x', '-'}))
        positions.push_back (i);

    if (positions.size () > 4)
      return {};

    vector<pair<string, string>> selections;
    int n = positions.size ();
    for (int i = 0; i < pow (2, n); i++) {
      int values[n];
      for (int j = 0; j < n; j++)
        values[j] = i >> j & 1;
      auto candidate = all_chars;
      for (int j = 0; j < n; j++) {
        auto value = values[j];
        auto c = candidate[positions[j]];
        candidate[positions[j]] =
            c == 'x' ? (value == 1 ? 'u' : 'n') : (value == 1 ? '1' : '0');
      }

      string candidate_inputs = candidate.substr (0, inputs.size ());
      string candidate_outputs =
          candidate.substr (inputs.size (), outputs.size ());
      auto propagation =
          otf_propagate (func, candidate_inputs, candidate_outputs);
      bool skip = false;
      for (auto &c : propagation) {
        if (c == '#') {
          skip = true;
          break;
        }
      }
      if (skip)
        continue;

      selections.push_back ({candidate_inputs, candidate_outputs});
    }

    int pairs_count = 0;
    {
      int n = all_chars.size ();
      for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++)
          pairs_count += 1;
      }
    }

    for (int i = 0; i < pairs_count; i++)
      diff_pairs.push_back ({});
    auto break_gc = [] (char gc) { return gc == 'u' || gc == '1' ? 1 : 0; };
    for (auto &selection : selections) {
      auto combined = selection.first + selection.second;
      int x = 0;
      int n = combined.size ();
      for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
          int c1 = break_gc (combined[i]);
          int c2 = break_gc (combined[j]);
          diff_pairs[x].insert (c1 ^ c2);
          x++;
        }
      }
    }

    // Add to the cache
    otf_2bit_cache.put (cache_key, diff_pairs);
  }

  int n = all_chars.size ();
  int x = -1;
  for (int i = 0; i < n; i++) {
    for (int j = i + 1; j < n; j++) {
      x += 1;
      if (mask[i] != '+' || mask[j] != '+')
        continue;

      if (!is_in (all_chars[i], {'-', 'x'}) ||
          !is_in (all_chars[j], {'-', 'x'}))
        continue;

      if (diff_pairs[x].size () != 1)
        continue;

      Equation eq;
      eq.diff = *diff_pairs[x].begin ();
      // Sort the IDs for non-ambiguous comparison
      uint32_t x, y;
      if (char_ids[i] < char_ids[j]) {
        x = char_ids[i];
        y = char_ids[j];
      } else {
        x = char_ids[j];
        y = char_ids[i];
      }
      eq.char_ids[0] = x;
      eq.char_ids[1] = y;
      equations.push_back (eq);
    }
  }

  return equations;
}

} // namespace SHA256