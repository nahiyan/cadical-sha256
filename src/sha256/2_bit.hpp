#ifndef _sha256_2_bit_hpp_INCLUDED
#define _sha256_2_bit_hpp_INCLUDED

#include "lru_cache.hpp"
#include "propagate.hpp"
#include "state.hpp"
#include "types.hpp"
#include "util.hpp"
#include <climits>
#include <list>
#include <map>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
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
// Checks GF(2) equations and returns conflicting equations (equations that
// conflicts with previously added ones)
inline vector<Equation> check_consistency (list<Equation *> &equations,
                                           bool exhaustive) {
  vector<Equation> conflicting_equations;
  map<uint32_t, shared_ptr<set<int32_t>>> rels;

  for (auto &equation : equations) {
    int lit1 = equation->ids[0];
    int lit2 = (equation->diff == 1 ? -1 : 1) * (equation->ids[1]);
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
          confl_eq.ids[0] = var1;
          confl_eq.ids[1] = var2;
          confl_eq.diff = lit2 < 0 ? 1 : 0;
          confl_eq.antecedent = equation->antecedent;
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

extern cache::lru_cache<string, pair<string, string>> otf_2bit_cache;
inline vector<Equation>
otf_2bit_eqs (vector<int> (*func) (vector<int> inputs), string inputs,
              string outputs, pair<vector<uint32_t>, vector<uint32_t>> ids,
              string mask, Stats *stats = NULL) {
  if (stats != NULL)
    stats->two_bit_total_calls++;

  vector<Equation> equations;
  pair<string, string> cols_xor;
  // printf ("Debug: %ld %ld %ld\n", inputs.size (), outputs.size (),
  //         char_ids.size ());
  assert (inputs.size () + outputs.size () == ids.first.size ());
  assert (inputs.size () + outputs.size () == ids.second.size ());
  assert (ids.first.size () == mask.size ());
  assert (ids.second.size () == mask.size ());

  // Look in the cache
  bool is_cached = false;
  string cache_key;
  {
    string func_str = to_string (reinterpret_cast<int64_t> (func));
    cache_key = func_str + " " + inputs + " " + outputs;
  }
  if (otf_2bit_cache.exists (cache_key)) {
    if (stats != NULL)
      stats->two_bit_cached_calls++;
    is_cached = true;
    cols_xor = otf_2bit_cache.get (cache_key);
  }

  string all_chars = inputs + outputs;
  assert (all_chars.size () == inputs.size () + outputs.size ());

  if (!is_cached) {
    vector<int> positions;
    for (int i = 0; i < int (all_chars.size ()); i++)
      if (is_in (all_chars[i], {'x', '-'}))
        positions.push_back (i);

    if (positions.size () > 4)
      return {};

    vector<pair<string, string>> selections[2];
    int n = positions.size (); // n is the placeholders count
    for (int block_i = 0; block_i < 2; block_i++)
      for (int i = 0; i < pow (2, n); i++) {
        int values[n];
        for (int j = 0; j < n; j++)
          values[j] = i >> j & 1;
        string candidate = all_chars;
        for (int j = 0; j < n; j++) {
          auto &value = values[j];
          // c: differential characteristic in the selected placeholder
          auto &c = candidate[positions[j]];
          assert (c == '-' || c == 'x');
          if (block_i == 0)
            c = c == 'x' ? (value == 1 ? 'u' : 'n')
                         : (value == 1 ? '1' : '0');
          else
            c = c == 'x' ? (value == 1 ? 'n' : 'u')
                         : (value == 1 ? '0' : '1');
        }

        string candidate_inputs = candidate.substr (0, inputs.size ());
        string candidate_outputs =
            candidate.substr (inputs.size (), outputs.size ());
        auto propagation =
            otf_propagate (func, candidate_inputs, candidate_outputs);
        string &prop_output = propagation.second;
        bool skip = false;
        for (auto &c : prop_output) {
          if (c == '#') {
            skip = true;
            break;
          }
        }
        if (skip)
          continue;

        selections[block_i].push_back (
            {candidate_inputs, candidate_outputs});
      }

    int pairs_count = 0;
    {
      int n = all_chars.size ();
      for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
          pairs_count += 1;
          // Each characteristic for each block
          cols_xor.first += "?";
          cols_xor.second += "?";
        }
      }
    }
    assert (int (cols_xor.first.size ()) == pairs_count);
    assert (int (cols_xor.second.size ()) == pairs_count);

    auto break_gc_f = [] (char gc) {
      assert (gc == 'u' || gc == '1' || gc == 'n' || gc == '0');
      return gc == 'u' || gc == '1' ? 1 : 0;
    };
    auto break_gc_g = [] (char gc) {
      assert (gc == 'u' || gc == '1' || gc == 'n' || gc == '0');
      return gc == 'n' || gc == '1' ? 1 : 0;
    };
    for (int block_i = 0; block_i < 2; block_i++) {
      auto &col_xor = block_i == 0 ? cols_xor.first : cols_xor.second;
      for (auto &selection : selections[block_i]) {
        auto combined = selection.first + selection.second;
        int x = -1;
        int n = combined.size ();
        for (int i = 0; i < n; i++) {
          for (int j = i + 1; j < n; j++) {
            assert (i != j);
            x++;

            if (!is_in (i, positions) || !is_in (j, positions)) {
              col_xor[x] = '?';
              continue;
            }

            auto break_gc = block_i == 0 ? break_gc_f : break_gc_g;
            uint8_t c1 = break_gc (combined[i]);
            uint8_t c2 = break_gc (combined[j]);
            char diff = (c1 ^ c2) == 0 ? '0' : '1';

            col_xor[x] = col_xor[x] == '?'    ? diff
                         : diff == col_xor[x] ? diff
                                              : 'v';
          }
        }
      }
    }

    // Add to the cache
    otf_2bit_cache.put (cache_key, cols_xor);
  }

  int n = all_chars.size ();
  for (int block_i = 0; block_i < 2; block_i++) {
    auto &col_xor = block_i == 0 ? cols_xor.first : cols_xor.second;
    auto &char_ids_ = block_i == 0 ? ids.first : ids.second;
    int x = -1;
    for (int i = 0; i < n; i++) {
      for (int j = i + 1; j < n; j++) {
        x += 1;

        if (col_xor[x] == '?' || col_xor[x] == 'v')
          continue;

        if (mask[i] != '+' || mask[j] != '+')
          continue;

        if (!is_in (all_chars[i], {'-', 'x'}) ||
            !is_in (all_chars[j], {'-', 'x'}))
          continue;

        Equation eq;
        assert (col_xor[x] == '0' || col_xor[x] == '1');
        eq.diff = col_xor[x] == '0' ? 0 : 1;
        // Sort the IDs for non-ambiguous comparison
        uint32_t x, y;
        if (char_ids_[i] < char_ids_[j]) {
          x = char_ids_[i];
          y = char_ids_[j];
        } else {
          x = char_ids_[j];
          y = char_ids_[i];
        }
        eq.ids[0] = x;
        eq.ids[1] = y;
        equations.push_back (eq);
      }
    }
  }

  return equations;
}

void load_two_bit_rules ();
} // namespace SHA256

#endif