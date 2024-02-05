#include "propagate.hpp"
#include "lru_cache.hpp"
#include "sha256.hpp"
#include "util.hpp"
#include <cassert>
#include <cmath>
#include <cstring>
#include <fstream>
#include <numeric>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

using namespace std;

namespace SHA256 {

map<char, vector<char>> symbols = {{'?', {'u', 'n', '1', '0'}},
                                   {'-', {'1', '0'}},
                                   {'x', {'u', 'n'}},
                                   {'0', {'0'}},
                                   {'u', {'u'}},
                                   {'n', {'n'}},
                                   {'1', {'1'}},
                                   {'3', {'0', 'u'}},
                                   {'5', {'0', 'n'}},
                                   {'7', {'0', 'u', 'n'}},
                                   {'A', {'u', '1'}},
                                   {'B', {'1', 'u', '0'}},
                                   {'C', {'n', '1'}},
                                   {'D', {'0', 'n', '1'}},
                                   {'E', {'u', 'n', '1'}}};
map<char, set<char>> symbols_set = {{'?', {'u', 'n', '1', '0'}},
                                    {'-', {'1', '0'}},
                                    {'x', {'u', 'n'}},
                                    {'0', {'0'}},
                                    {'u', {'u'}},
                                    {'n', {'n'}},
                                    {'1', {'1'}},
                                    {'3', {'0', 'u'}},
                                    {'5', {'0', 'n'}},
                                    {'7', {'0', 'u', 'n'}},
                                    {'A', {'u', '1'}},
                                    {'B', {'1', 'u', '0'}},
                                    {'C', {'n', '1'}},
                                    {'D', {'0', 'n', '1'}},
                                    {'E', {'u', 'n', '1'}}};

cache::lru_cache<string, string> otf_prop_cache (5e6);
string otf_propagate (vector<int> (*func) (vector<int> inputs),
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
    if (otf_prop_cache.exists (cache_key)) {
      return otf_prop_cache.get (cache_key);
    }
  }

  int outputs_size = outputs.size ();
  auto conforms_to = [] (char c1, char c2) {
    auto c1_chars = symbols[c1], c2_chars = symbols[c2];
    for (auto &c : c1_chars)
      if (find (c2_chars.begin (), c2_chars.end (), c) == c2_chars.end ())
        return false;
    return true;
  };

  vector<vector<char>> iterables_list;
  for (auto &input : inputs) {
    auto it = symbols.find (input);
    if (it != symbols.end ())
      iterables_list.push_back (it->second);
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

  auto gc_from_set = [] (set<char> &set) {
    for (auto &entry : symbols_set)
      if (set == entry.second)
        return entry.first;
    return '#';
  };

  string propagated_output = "";
  for (auto &p : possibilities)
    propagated_output += gc_from_set (p);

  // Cache the result
  otf_prop_cache.put (cache_key, propagated_output);
  return propagated_output;
}

} // namespace SHA256