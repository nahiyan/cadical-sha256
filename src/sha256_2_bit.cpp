#include "sha256_2_bit.hpp"
#include "sha256_propagate.hpp"
#include "sha256_state.hpp"
#include "sha256_util.hpp"

#include "NTL/GF2.h"
#include "NTL/mat_GF2.h"
#include "NTL/vec_GF2.h"
#include <cassert>
#include <climits>
#include <fstream>
#include <memory>
#include <set>

namespace SHA256 {
unordered_map<string, string> two_bit_rules;

void load_two_bit_rules (const char *path) {
  std::ifstream db (path);
  if (!db) {
    printf ("Rules database not found. Can you ensure that '%s' "
            "exists in the current working directory?\n",
            path);
    exit (1);
  }
  int count = 0;
  std::string key, value;
  int id;
  while (db >> id >> key >> value) {
    key = to_string (id) + key;

    two_bit_rules.insert ({key, value});
    count++;
  }

  printf ("Loaded %d rules into %ld buckets\n", count,
          two_bit_rules.bucket_count ());
}

void derive_two_bit_equations (TwoBit &two_bit, State &state) {
  auto derive_from_matrix = [] (TwoBit &two_bit, string &key,
                                string &matrix, vector<SoftWord *> &inputs,
                                vector<Word *> &outputs, int col_index) {
    int matrix_i = -1;
    int words_count = inputs.size () + outputs.size ();
    for (int k = 0; k < 2; k++) {
      for (int i = 0; i < words_count; i++) {
        for (int j = i + 1; j < words_count; j++) {
          matrix_i++;
          if (matrix[matrix_i] == '2' || words_count - 1 == i ||
              words_count - 1 == j)
            continue;

          uint8_t diff = matrix[matrix_i] == '1' ? 0 : 1;
          uint32_t selected_ids[] = {inputs[i]->char_ids[col_index],
                                     inputs[j]->char_ids[col_index]};

          Equation equation;
          equation.char_ids[0] = selected_ids[0];
          equation.char_ids[1] = selected_ids[1];
          equation.diff = diff;
          two_bit.equations[k].push_back (equation);

          // printf ("Equation: %s %s %s\n", equation.names[0].c_str (),
          //         diff == 0 ? "=" : "=/=", equation.names[1].c_str ());

          // Increment the constraints count
          for (int x = 0; x < 2; x++) {
            auto word = inputs[x == 0 ? i : j];
            tuple<uint32_t, uint32_t, uint32_t> key = {
                word->ids_f[col_index],
                word->ids_g[col_index],
                word->char_ids[col_index],
            };
            if (two_bit.bit_constraints_count.find (key) !=
                two_bit.bit_constraints_count.end ())
              two_bit.bit_constraints_count[key] = 1;
            else
              two_bit.bit_constraints_count[key]++;
          }

          // Map the equation variables (if they don't exist)
          for (int i = 0; i < 2; i++)
            if (two_bit.aug_mtx_var_map.find (selected_ids[i]) ==
                two_bit.aug_mtx_var_map.end ())
              two_bit.aug_mtx_var_map[selected_ids[i]] =
                  two_bit.aug_mtx_var_map.size ();

          // Add all the related variables to the equation
          vector<int> vars;
          for (auto &word : inputs) {
            vars.push_back (word->ids_f[col_index]);
            vars.push_back (word->ids_g[col_index]);
            for (int x = 0; x < 4; x++)
              vars.push_back (word->char_ids[col_index] + j);
          }
          for (auto &word : outputs) {
            vars.push_back (word->ids_f[col_index]);
            vars.push_back (word->ids_g[col_index]);
            for (int x = 0; x < 4; x++)
              vars.push_back (word->char_ids[col_index] + j);
          }

          auto equation_vars_it = two_bit.equation_vars.find (equation);
          if (equation_vars_it == two_bit.equation_vars.end ())
            two_bit.equation_vars.insert ({equation, {}});

          auto &equation_vars = two_bit.equation_vars[equation];
          assert (!vars.empty ());
          for (auto &var : vars)
            equation_vars.push_back (var);
        }
      }
    }
  };

  for (int i = 0; i < state.order; i++) {
    auto &step_operations = state.operations[i];
    auto &step_state = state.steps[i];

    if (i >= 16) {
      {
        // s0
        auto &inputs_ = step_operations.s0.inputs;
        vector<Word *> outputs = {&step_state.s0};
        auto &output_chars = step_state.s0.chars;

        for (int j = 0; j < 32; j++) {
          vector<SoftWord *> inputs = {&inputs_[0], &inputs_[1]};
          if (j >= 3)
            inputs.push_back (&inputs_[2]);

          string key;
          key += to_string (j >= 3 ? TWO_BIT_XOR3_ID : TWO_BIT_XOR2_ID);
          for (auto &input : inputs)
            key += *input->chars[j];
          key += output_chars[j];
          string value = two_bit_rules[key];

          // TODO: Naming the variables shouldn't be done outside
          int indices[] = {(31 - j + 7) % 32, (31 - j + 18) % 32,
                           31 - j + 3};
          if (!value.empty ())
            derive_from_matrix (two_bit, key, value, inputs, outputs, j);
        }
      }
      {
        // s1
        auto &inputs_ = step_operations.s1.inputs;
        vector<Word *> outputs = {&step_state.s1};
        auto &output_char = step_state.s1.chars;

        for (int j = 0; j < 32; j++) {
          vector<SoftWord *> inputs = {&inputs_[0], &inputs_[1]};
          if (j >= 10)
            inputs.push_back (&inputs_[2]);

          string key;
          key += to_string (j >= 10 ? TWO_BIT_XOR3_ID : TWO_BIT_XOR2_ID);
          for (auto &input : inputs)
            key += *input->chars[j];
          key += output_char[j];
          string value = two_bit_rules[key];

          int indices[] = {(31 - j + 17) % 32, (31 - j + 19) % 32,
                           31 - j + 10};
          if (!value.empty ())
            derive_from_matrix (two_bit, key, value, inputs, outputs, j);
        }
      }
    }

    {
      // sigma0
      auto &inputs_ = step_operations.sigma0.inputs;
      vector<Word *> outputs = {&step_state.sigma0};
      auto &output_chars = step_state.sigma0.chars;
      for (int j = 0; j < 32; j++) {
        vector<SoftWord *> inputs = {&inputs_[0], &inputs_[1], &inputs_[2]};
        string key;
        key += to_string (TWO_BIT_XOR3_ID);
        for (auto &input : inputs)
          key += *input->chars[j];
        key += output_chars[j];
        string value = two_bit_rules[key];

        int indices[] = {(31 - j + 2) % 32, (31 - j + 13) % 32,
                         (31 - j + 22) % 32};
        if (!value.empty ())
          derive_from_matrix (two_bit, key, value, inputs, outputs, j);
      }
    }
    {
      // sigma1
      auto &inputs_ = step_operations.sigma1.inputs;
      vector<Word *> outputs = {&step_state.sigma1};
      auto &output_chars = step_state.sigma1.chars;
      for (int j = 0; j < 32; j++) {
        vector<SoftWord *> inputs = {&inputs_[0], &inputs_[1], &inputs_[2]};
        string key;
        key += to_string (TWO_BIT_XOR3_ID);
        for (auto &input : inputs)
          key += *input->chars[j];
        key += output_chars[j];
        string value = two_bit_rules[key];

        int indices[] = {(31 - j + 6) % 32, (31 - j + 11) % 32,
                         (31 - j + 25) % 32};
        if (!value.empty ())
          derive_from_matrix (two_bit, key, value, inputs, outputs, j);
      }
    }
    {
      // maj
      auto &inputs_ = step_operations.maj.inputs;
      vector<Word *> outputs = {&step_state.maj};
      auto &output_chars = step_state.maj.chars;
      for (int j = 0; j < 32; j++) {
        vector<SoftWord *> inputs = {&inputs_[0], &inputs_[1], &inputs_[2]};
        string key;
        key += to_string (TWO_BIT_MAJ_ID);
        for (auto &input : inputs)
          key += *input->chars[j];
        key += output_chars[j];
        string value = two_bit_rules[key];
        if (!value.empty ())
          derive_from_matrix (two_bit, key, value, inputs, outputs, j);
      }
    }
    {
      // ch
      auto &inputs_ = step_operations.ch.inputs;
      vector<Word *> outputs = {&step_state.ch};
      auto &output_chars = step_state.ch.chars;
      for (int j = 0; j < 32; j++) {
        vector<SoftWord *> inputs = {&inputs_[0], &inputs_[1], &inputs_[2]};
        string key;
        key += to_string (TWO_BIT_IF_ID);
        for (auto &input : inputs)
          key += *input->chars[j];
        key += output_chars[j];
        string value = two_bit_rules[key];
        if (!value.empty ())
          derive_from_matrix (two_bit, key, value, inputs, outputs, j);
      }
    }
  }
}

// Checks GF(2) equations and returns conflicting equations (equations that
// conflicts with previously added ones)
vector<Equation> check_consistency (vector<Equation> &equations,
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
      auto new_set =
          std::make_shared<std::set<int>> (std::set<int>{lit1, lit2});
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
  int equations_n = two_bit.equations[block_index].size ();
  coeff_matrix.SetDims (equations_n, variables_n);
  rhs.SetLength (equations_n);

  // Construct the coefficient matrix
  for (int eq_index = 0; eq_index < equations_n; eq_index++) {
    auto &equation = two_bit.equations[block_index][eq_index];
    int &x = two_bit.aug_mtx_var_map[equation.char_ids[0]];
    int &y = two_bit.aug_mtx_var_map[equation.char_ids[1]];
    for (int col_index = 0; col_index < variables_n; col_index++)
      coeff_matrix[eq_index][col_index] =
          NTL::to_GF2 (col_index == x || col_index == y ? 1 : 0);

    rhs.put (eq_index, equation.diff);
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
  int equations_n = two_bit.equations[block_index].size ();
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
  // printf ("Debug: found inconsistencies (%d): %d equations\n",
  //         inconsistent_eq_n, sum_dec_from_bin (inconsistency_deref));

  std::set<int> confl_clause_lits;
  for (int eq_index = 0; eq_index < equations_n; eq_index++) {
    if (inconsistency_deref[eq_index] == 0)
      continue;

    auto &equation = two_bit.equations[block_index][eq_index];
    auto eq_vars_result = two_bit.equation_vars.find (equation);
    assert (eq_vars_result != two_bit.equation_vars.end ());

    // printf ("Blocking equation: %d %s %d\n", equation.char_ids[0],
    //         equation.diff == 1 ? "=/=" : "=", equation.char_ids[1]);

    // Instances refer to the function instances
    auto &vars = eq_vars_result->second;
    assert (!vars.empty ());
    for (auto &var : vars) {
      auto value = partial_assignment.get (var);
      assert (partial_assignment.get (var) != LIT_UNDEF);
      auto polarity = value == LIT_TRUE ? -1 : 1;
      confl_clause_lits.insert (polarity * var);
    }
  }
  assert (!confl_clause_lits.empty ());

  // Push the blocking/conflict clause
  vector<int> clause;
  for (auto &lit : confl_clause_lits)
    clause.push_back (lit);
  assert (!clause.empty ());
  external_clauses.push_back (clause);

  return true;
}

map<tuple<vector<int> (*) (vector<int>), string, string>, vector<set<int>>>
    otf_2bit_cache;
// TODO: Add caching mechanism
vector<Equation> otf_2bit_eqs (vector<int> (*func) (vector<int> inputs),
                               string inputs, string outputs,
                               vector<uint32_t> char_ids, string mask) {
  vector<Equation> equations;
  vector<set<int>> diff_pairs;
  assert (inputs.size () + outputs.size () == char_ids.size ());
  assert (char_ids.size () == mask.size ());

  bool is_cached = false;
  auto otf_2bit_cache_it = otf_2bit_cache.find ({func, inputs, outputs});
  if (otf_2bit_cache_it != otf_2bit_cache.end ()) {
    is_cached = true;
    diff_pairs = otf_2bit_cache_it->second;
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
    otf_2bit_cache[{func, inputs, outputs}] = diff_pairs;
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
      eq.char_ids[0] = char_ids[i];
      eq.char_ids[1] = char_ids[j];
      equations.push_back (eq);
    }
  }

  return equations;
}

} // namespace SHA256