#ifndef _sha256_propagate_hpp_INCLUDED
#define _sha256_propagate_hpp_INCLUDED

#include "lru_cache.hpp"
#include "types.hpp"
#include "util.hpp"
#include <cstdint>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

namespace SHA256 {
// Break down a differential characteristic into a list of possibilities
inline vector<char> get_symbols (char key) {
  switch (key) {
  case '?':
    return {'u', 'n', '1', '0'};
  case '-':
    return {'1', '0'};
  case 'x':
    return {'u', 'n'};
  case '0':
    return {'0'};
  case 'u':
    return {'u'};
  case 'n':
    return {'n'};
  case '1':
    return {'1'};
  case '3':
    return {'0', 'u'};
  case '5':
    return {'0', 'n'};
  case '7':
    return {'0', 'u', 'n'};
  case 'A':
    return {'u', '1'};
  case 'B':
    return {'1', 'u', '0'};
  case 'C':
    return {'n', '1'};
  case 'D':
    return {'0', 'n', '1'};
  case 'E':
    return {'u', 'n', '1'};
  default:
    return {}; // Return an empty vector for unknown keys
  }
}

// Get the differential characteristic from a list of possibilities
inline char get_symbol (const set<char> &symbols) {
  if (symbols == set<char>{'u', 'n', '1', '0'})
    return '?';
  else if (symbols == set<char>{'1', '0'})
    return '-';
  else if (symbols == set<char>{'u', 'n'})
    return 'x';
  else if (symbols == set<char>{'0'})
    return '0';
  else if (symbols == set<char>{'u'})
    return 'u';
  else if (symbols == set<char>{'n'})
    return 'n';
  else if (symbols == set<char>{'1'})
    return '1';
  else if (symbols == set<char>{'0', 'u'})
    return '3';
  else if (symbols == set<char>{'0', 'n'})
    return '5';
  else if (symbols == set<char>{'0', 'u', 'n'})
    return '7';
  else if (symbols == set<char>{'u', '1'})
    return 'A';
  else if (symbols == set<char>{'1', 'u', '0'})
    return 'B';
  else if (symbols == set<char>{'n', '1'})
    return 'C';
  else if (symbols == set<char>{'0', 'n', '1'})
    return 'D';
  else if (symbols == set<char>{'u', 'n', '1'})
    return 'E';

  return '#';
}

extern cache::lru_cache<string, string> otf_prop_cache;
inline string otf_propagate (vector<int> (*func) (vector<int> inputs),
                             string inputs, string outputs) {
  assert (func == add_ ? outputs.size () == 3 : true);

  FunctionId func_id = func == add_   ? add
                       : func == xor_ ? xor3
                       : func == maj_ ? maj
                                      : ch;

  // Look in the cache
  string cache_key;
  {
    stringstream ss;
    ss << func_id << " " << inputs << " " << outputs;
    cache_key = ss.str ();
    if (otf_prop_cache.exists (cache_key))
      return otf_prop_cache.get (cache_key);
  }

  int outputs_size = outputs.size ();
  auto conforms_to = [] (char c1, char c2) {
    vector<char> c1_chars = get_symbols (c1), c2_chars = get_symbols (c2);
    for (auto &c : c1_chars)
      if (find (c2_chars.begin (), c2_chars.end (), c) == c2_chars.end ())
        return false;
    return true;
  };

  vector<vector<char>> iterables_list;
  for (auto &input : inputs) {
    vector<char> symbols = get_symbols (input);
    if (!symbols.empty ())
      iterables_list.push_back (symbols);
  }

  set<char> possibilities[outputs_size];
  auto combos = cartesian_product (iterables_list);
  for (auto &combo : combos) {
    vector<int> inputs_f, inputs_g;
    for (auto &c : combo) {
      switch (c) {
      case 'u':
        inputs_f.push_back (1);
        inputs_g.push_back (0);
        break;
      case 'n':
        inputs_f.push_back (0);
        inputs_g.push_back (1);
        break;
      case '1':
        inputs_f.push_back (1);
        inputs_g.push_back (1);
        break;
      case '0':
        inputs_f.push_back (0);
        inputs_g.push_back (0);
        break;
      }
    }

    vector<int> outputs_f, outputs_g;
    outputs_f = func (inputs_f);
    outputs_g = func (inputs_g);

    vector<char> outputs_;
    bool skip = false;
    for (int i = 0; i < outputs_size; i++) {
      int x = outputs_f[i], x_ = outputs_g[i];
      outputs_.push_back (x == 1 && x_ == 1   ? '1'
                          : x == 1 && x_ == 0 ? 'u'
                          : x == 0 && x_ == 1 ? 'n'
                                              : '0');
      if (!conforms_to (outputs_[i], outputs[i])) {
        skip = true;
        break;
      }
    }

    if (skip)
      continue;

    for (int i = 0; i < outputs_size; i++)
      possibilities[i].insert ((outputs_[i]));
  }

  string propagated_output = "";
  for (auto &p : possibilities)
    propagated_output += get_symbol (p);

  // Cache the result
  otf_prop_cache.put (cache_key, propagated_output);
  return propagated_output;
}

void load_prop_rules ();
} // namespace SHA256

#endif