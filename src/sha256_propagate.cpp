#include "sha256_propagate.hpp"
#include "sha256.hpp"
#include "sha256_util.hpp"
#include <cassert>
#include <cmath>
#include <cstring>
#include <fstream>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

namespace SHA256 {
struct OrderedValue {
  char value;
  uint8_t order; // Order will be 31 max and 8 bits can hold 0-255
};

unordered_map<string, string> io_prop_rules;

// Function to calculate the Cartesian product of multiple vectors of
// characters
vector<string> cartesian_product (vector<std::vector<char>> input) {
  vector<string> result;
  int numVectors = input.size ();
  vector<int> indices (numVectors, 0);

  while (true) {
    std::string currentProduct;
    for (int i = 0; i < numVectors; ++i)
      currentProduct.push_back (input[i][indices[i]]);

    result.push_back (currentProduct);

    int j = numVectors - 1;
    while (j >= 0 && indices[j] == int (input[j].size ()) - 1) {
      indices[j] = 0;
      j--;
    }

    if (j < 0)
      break;

    indices[j]++;
  }

  return result;
}

bool is_in (char x, vector<char> chars) {
  return std::find (chars.begin (), chars.end (), x) != chars.end ();
}
bool is_in (int x, vector<int> y) {
  return std::find (y.begin (), y.end (), x) != y.end ();
}

int64_t _int_diff (char *chars) {
  size_t n = strlen (chars);
  int64_t value = 0;
  for (size_t i = 0; i < n; i++) {
    char gc = chars[n - 1 - i];
    if (!is_in (gc, {'u', 'n', '-', '1', '0'}))
      return -1;

    value += (gc == 'u' ? 1 : gc == 'n' ? -1 : 0) * int64_t (pow (2, i));
  }

  return e_mod (value, pow (2, n));
}

int64_t adjust_constant (string word, int64_t constant,
                         vector<char> adjustable_gcs) {
  if (adjustable_gcs.size () == 0) {
    adjustable_gcs = {'x', 'n', '5', 'C', 'D', '?'};
  }
  size_t n = word.size ();
  for (size_t i = 0; i < n; i++) {
    char gc = word[n - 1 - i];
    if (is_in (gc, adjustable_gcs))
      constant += pow (2, i);
  }

  return e_mod (constant, pow (2, n));
}

bool is_congruent (int64_t a, int64_t b, int64_t m) {
  return (a - b) % m == 0;
}

tuple<vector<OrderedValue>, int64_t>
process_var_cols (vector<string> var_cols) {
  vector<OrderedValue> vars;
  int64_t const_value = 0;
  int cols_count = var_cols.size ();
  for (int i = 0; i < cols_count; i++) {
    auto &col = var_cols[i];
    int rows_count = col.size ();
    for (int j = 0; j < rows_count; j++) {
      auto &var = col[j];
      if (var == 'v')
        vars.push_back ({-1, uint8_t (i)});
      else
        const_value += (var == '1' ? 1 : 0) * int64_t (pow (2, i));
    }
  }

  return {vars, const_value};
}

bool _can_overflow (vector<string> var_cols, vector<uint8_t> bits) {
  int bits_count = bits.size ();
  int64_t value = 0, max_value = 0;
  for (int i = 0; i < bits_count; i++) {
    value += bits[i] * int64_t (pow (2, i));
    // TODO: You don't need a loop to calculate the max value
    max_value += int64_t (pow (2, i));
  }

  auto var_cols_processed = process_var_cols (var_cols);
  vector<OrderedValue> vars = get<0> (var_cols_processed);
  int64_t const_value = get<1> (var_cols_processed);

  int64_t m = pow (2, bits_count);
  int vars_count = vars.size ();
  for (int64_t i = pow (2, vars_count); i >= 0; i--) {
    int64_t candidate_value = const_value;
    for (int j = 0; j < vars_count; j++) {
      auto &var = vars[j];
      candidate_value += (i >> j & 1) * int64_t (pow (2, var.order));
    }
    if (candidate_value <= max_value)
      continue;
    if (is_congruent (candidate_value, value, m))
      return true;
  }

  return false;
}

vector<string> gen_vars (vector<string> words) {
  int cols_count = words[0].size ();
  vector<string> var_cols;
  for (int i = 0; i < cols_count; i++) {
    var_cols.push_back ("");
  }

  int words_count = words.size ();
  for (int i = 0; i < words_count; i++) {
    for (int j = cols_count - 1; j >= 0; j--) {
      char gc = words[i][j];
      bool is_msb = j == 0;
      if (gc == 'x' && !is_msb) {
        var_cols[j - 1].push_back ('v');
      } else if (is_in (gc, {'?', '7', 'E'})) {
        var_cols[j].push_back ('v');
        if (!is_msb)
          var_cols[j - 1].push_back ('v');
      } else if (is_in (gc, {'3', '5', 'A', 'B', 'C', 'D'})) {
        var_cols[j].push_back ('v');
      }
    }
  }

  // Deal with the constants but treat them as derived variables
  for (int i = cols_count - 1; i >= 0; i--) {
    int sum = 0;
    for (int j = 0; j < words_count; j++)
      sum += words[j][i] == 'u' ? 1 : 0;

    assert (sum >= 0 && sum <= 2);
    if (sum == 2)
      var_cols[i - 1].push_back ('1');
    else if (sum == 1)
      var_cols[i].push_back ('1');
  }

  return var_cols;
}

string brute_force (vector<string> var_cols, int64_t constant,
                    int64_t min_gt) {
  auto var_cols_processed = process_var_cols (var_cols);
  vector<OrderedValue> vars = get<0> (var_cols_processed);
  int64_t const_value = get<1> (var_cols_processed);
  int vars_count = vars.size ();
  vector<vector<int>> solutions;
  for (int64_t i = 0; i < pow (2, vars_count); i++) {
    int64_t sum = const_value;
    vector<int> values (vars_count);
    for (int j = 0; j < vars_count; j++) {
      values[j] = i >> j & 1;
      sum += values[j] * int64_t (pow (2, vars[j].order));
    }
    if (min_gt == -1 && sum != constant)
      continue;
    if (min_gt != -1 && sum <= min_gt)
      continue;
    solutions.push_back (values);
  }

  int sols_count = solutions.size ();
  vector<char> pattern (vars_count);
  for (int i = 0; i < sols_count; i++) {
    auto solution = solutions[i];
    for (int j = 0; j < vars_count; j++) {
      if (pattern[j] == 'v')
        continue;
      if (pattern[j] != '0' && pattern[j] != '1' && pattern[j] != 'v')
        pattern[j] = solution[i] == 1 ? '1' : '0';

      bool matching = (pattern[j] == '1' && solution[j] == 1) ||
                      (pattern[j] == '0' && solution[j] == 0);
      if (!matching)
        pattern[j] = 'v';
    }
  }

  string pattern_ (pattern.begin (), pattern.end ());
  return pattern_;
}

vector<string> apply_grounding (vector<string> words,
                                vector<string> var_cols,
                                vector<char> var_values) {
  // Remove constants from columns
  int i = 0;
  for (auto &col : var_cols) {
    string new_col;
    for (auto &var : col) {
      if (var == 'v')
        new_col += 'v';
    }
    var_cols[i++] = new_col;
  }

  int cols_count = words[0].size (), var_index = 0;
  vector<string> derived_words (words);
  for (int i = cols_count - 1; i >= 0; i--) {
    auto &current_col = var_cols[i];
    auto next_col = i != 0 ? var_cols[i - 1] : "";
    int new_var_index = var_index + current_col.size ();
    set<char> next_col_set, current_col_set;
    for (int j = 0; j < int (next_col.size ()); j++)
      next_col_set.insert (var_values[j + new_var_index]);
    for (int j = 0; j < int (current_col.size ()); j++)
      current_col_set.insert (var_values[j + var_index]);

    for (int j = 0; j < int (words.size ()); j++) {
      char gc = words[j][i];

      if (gc == 'x' && next_col_set.size () == 1) {
        char value = *next_col_set.begin ();
        if (value == 'v')
          continue;
        derived_words[j][i] = value == '1' ? 'u' : 'n';
      } else if (is_in (gc, {'3', '5', 'A', 'B', 'C', 'D'}) &&
                 current_col_set.size () == 1) {
        char value = *current_col_set.begin ();
        if (value == 'v')
          continue;
        switch (gc) {
        case '3':
          derived_words[j][i] = value == '0' ? '0' : 'u';
          break;
        case '5':
          derived_words[j][i] = value == '0' ? 'n' : '0';
          break;
        case 'A':
          derived_words[j][i] = value == '0' ? '1' : 'u';
          break;
        case 'B':
          derived_words[j][i] = value == '0' ? '-' : 'u';
          break;
        case 'C':
          derived_words[j][i] = value == '0' ? 'n' : '1';
          break;
        case 'D':
          derived_words[j][i] = value == '0' ? 'n' : '-';
          break;
        }
      } else if (is_in (gc, {'7', 'E', '?'})) {
        if (current_col_set.size () == 1) {
          char value = *current_col_set.begin ();
          if (value == 'v')
            continue;
          derived_words[j][i] = value == '1' ? (gc == '?'   ? '-'
                                                : gc == '7' ? '0'
                                                            : '1')
                                             : 'n';
        } else if (next_col_set.size () == 1) {
          char value = *current_col_set.begin ();
          if (value == 'v')
            continue;
          derived_words[j][i] = 'u';
        }
      }
    }

    var_index = new_var_index;
  }

  return derived_words;
}

vector<string> derive_words (vector<string> words, int64_t constant) {
  int n = words[0].size (), m = words.size ();
  // Skip if all words are grounded
  bool all_grounded = true;
  for (int i = 0; i < m; i++)
    for (int j = 0; j < n; j++)
      if (!is_in (words[i][j], {'n', 'u', '1', '0', '-'}))
        all_grounded = false;

  if (all_grounded)
    return words;

  // Generate variables
  auto var_cols = gen_vars (words);

  // Adjust constant
  for (int i = 0; i < m; i++)
    constant = adjust_constant (words[i], constant);

  // Linear scan
  struct Island {
    vector<string> cols;
    vector<uint8_t> bits;
  } stash;
  vector<Island> islands;
  vector<int> overflow_brute_force_indices;
  for (int i = n - 1; i >= 0; i--) {
    // Skip if there's nothing in the stash and there's no variable either
    if (stash.cols.size () == 0 && var_cols[i].size () == 0)
      continue;

    uint8_t bit = constant >> (n - i - 1) & 1;
    stash.bits.push_back (bit);
    stash.cols.push_back (var_cols[i]);

    // Check if it can overflow
    bool can_overflow = _can_overflow (stash.cols, stash.bits);

    // If it cannot overflow, it should be cut off
    bool island_ends = can_overflow ? false : true;

    bool all_zero_diff = true;
    for (auto &word : words)
      all_zero_diff &= is_in (word[i], {'1', '0', '-'});
    if (bit == 0 && all_zero_diff) {
      island_ends = true;
      if (can_overflow)
        overflow_brute_force_indices.push_back (islands.size ());
    }

    // Flush the stash
    if (i == 0) {
      island_ends = true;
      if (can_overflow && can_overflow)
        overflow_brute_force_indices.push_back (islands.size ());
    }

    if (island_ends) {
      auto island = Island (stash);
      islands.push_back (island);
      stash.bits = {};
      stash.cols = {};
    }
  }

  // Derive the variable values
  vector<char> var_values;
  int island_index = 0;
  for (auto &island : islands) {
    int64_t sum = 0;
    int n = island.bits.size ();
    for (int i = 0; i < n; i++)
      sum += island.bits[i] * int64_t (pow (2, i));

    string propagation;
    if (is_in (island_index, overflow_brute_force_indices)) {
      int64_t min_gt = int64_t (pow (2, n)) - 1;
      propagation = brute_force (island.cols, -1, min_gt);
    } else {
      propagation = brute_force (island.cols, sum);
    }

    int local_index = 0;
    for (int i = 0; i < int (island.cols.size ()); i++) {
      auto &col = island.cols[i];
      for (auto &var : col) {
        if (var != 'v')
          continue;
        auto value = propagation[local_index++];
        var_values.push_back (value);
      }
    }

    island_index++;
  }

  auto derived_words = apply_grounding (words, var_cols, var_values);
  return derived_words;
}

void load_prop_rules (string path) {
  ifstream rules_db (path);
  int id;
  string input, output;
  while (rules_db >> id >> input >> output) {
    string key = to_string (id) + input;
    io_prop_rules.insert ({key, output});
  }
}

string get_prop_rule (int id, string input) {
  string key = to_string (id) + input;
  return io_prop_rules[key];
}

string propagate (int id, vector<string> input_words, string original) {
  int n = input_words[0].size (), m = input_words.size ();
  string output_word (n, '?');
  for (int i = 0; i < n; i++) {
    string input = "";
    for (int j = 0; j < m; j++)
      input += input_words[j][i];
    string output = get_prop_rule (id, input);
    if (output.size () == 0) {
      output_word[i] = original[i];
      continue;
    }
    output_word[i] = output[0];
  }

  return output_word;
}

void prop_with_int_diff (int equation_id, vector<string> words,
                         State &state, int step) {
  vector<int> underived_indices;
  int words_count = words.size ();
  vector<int64_t> word_diffs (words_count);
  for (int i = 0; i < words_count; i++) {
    int64_t int_diff = _int_diff ((char *) words[i].c_str ());
    // cout << step << " " << words[i] << " " << int_diff << endl;
    if (int_diff != -1)
      word_diffs[i] =
          ((i == 0 || (equation_id == ADD_A_ID && i == 2)) ? 1 : -1) *
          int_diff;
    else
      underived_indices.push_back (i);
  }

  int underived_count = underived_indices.size ();
  if (underived_count != 1 && underived_count != 2)
    return;
  // cout << underived_count << endl;
  int64_t constant = 0;
  for (int i = 0; i < words_count; i++)
    constant += is_in (i, underived_indices) ? 0 : word_diffs[i];
  constant = e_mod (constant, int64_t (pow (2, 32)));

  for (int i = 0; i < underived_count; i++) {
    auto index = underived_indices[i];
    if (index == 0 || (equation_id == ADD_A_ID && index == 2))
      constant *= -1;
  }
  vector<string> underived_words;
  for (int i = 0; i < underived_count; i++)
    underived_words.push_back (words[underived_indices[i]]);
  auto derived_words = derive_words (underived_words, constant);

  auto set_word = [] (string &new_word, Word &old_word) {
    old_word.chars = new_word;
  };

  for (int i = 0; i < underived_count; i++) {
    auto index = underived_indices[i];
    string new_word = derived_words[i];
    switch (equation_id) {
    case ADD_W_ID:
      switch (index) {
      case 0:
        set_word (new_word, state.steps[step].w);
        break;
      case 1:
        set_word (new_word, state.steps[step].s1);
        break;
      case 2:
        set_word (new_word, state.steps[step - 7].w);
        break;
      case 3:
        set_word (new_word, state.steps[step].s0);
        break;
      case 4:
        set_word (new_word, state.steps[step - 16].w);
        break;
      }
      break;
    case ADD_E_ID:
      switch (index) {
      case 0:
        set_word (new_word, state.steps[ABS_STEP (step)].e);
        break;
      case 1:
        set_word (new_word, state.steps[ABS_STEP (step - 4)].a);
        break;
      case 2:
        set_word (new_word, state.steps[ABS_STEP (step - 4)].e);
        break;
      case 3:
        set_word (new_word, state.steps[step].sigma1);
        break;
      case 4:
        set_word (new_word, state.steps[step].ch);
        break;
      case 5:
        set_word (new_word, state.steps[step].w);
        break;
      }
      break;
    case ADD_A_ID:
      switch (index) {
      case 0:
        set_word (new_word, state.steps[ABS_STEP (step)].a);
        break;
      case 1:
        set_word (new_word, state.steps[ABS_STEP (step)].e);
        break;
      case 2:
        set_word (new_word, state.steps[ABS_STEP (step - 4)].a);
        break;
      case 3:
        set_word (new_word, state.steps[step].sigma0);
        break;
      case 4:
        set_word (new_word, state.steps[step].maj);
        break;
      }
      break;
    }
  }
}

} // namespace SHA256