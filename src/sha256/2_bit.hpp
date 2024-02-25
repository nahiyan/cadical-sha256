#ifndef _sha256_2_bit_hpp_INCLUDED
#define _sha256_2_bit_hpp_INCLUDED

#include "lru_cache.hpp"
#include "propagate.hpp"
#include "state.hpp"
#include "types.hpp"
#include "util.hpp"
#include <list>
#include <map>
#include <sstream>
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

  // TODO: Improve efficiency
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
          // TODO: Add 2-block support
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