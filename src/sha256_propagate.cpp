#include "sha256_propagate.hpp"
#include "sha256.hpp"
#include "sha256_2_bit.hpp"
#include "sha256_util.hpp"
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <fstream>
#include <numeric>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

using namespace std;

namespace SHA256 {
struct OrderedValue {
  char value;
  uint8_t order; // Order will be 31 max and 8 bits can hold 0-255
};

unordered_map<string, string> io_prop_rules;
// Almost same as IO prop rules but specific for addition
map<pair<string, char>, pair<string, string>> add_prop_rules;

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

int64_t _int_diff (string word) {
  size_t n = word.size ();
  int64_t value = 0;
  for (size_t i = 0; i < n; i++) {
    char gc = word[n - 1 - i];
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
  vector<string> var_cols (cols_count);

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
    if (sum == 2 && i - 1 >= 0)
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
  auto count_vars = [] (vector<string> cols) {
    int vars_count = 0;
    for (auto &col : cols) {
      for (auto &c : col) {
        if (c != 'v')
          continue;
        vars_count++;
      }
    }

    return vars_count;
  };

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
  int vars_count = count_vars (var_cols);

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

    // Limit the number of variables
    int vars_count = count_vars (stash.cols);
    if (vars_count > 10)
      break;

    // Check if it can overflow
    // printf ("Debug: finding 'can overflow' start %d\n", vars_count);
    // fflush (stdout);
    bool can_overflow = _can_overflow (stash.cols, stash.bits);
    // printf ("Debug: finding 'can overflow' end\n");
    // fflush (stdout);

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

  // Fill in missing values
  for (int i = int (var_values.size ()); i < vars_count; i++)
    var_values.push_back (-1);
  assert (int (var_values.size ()) == vars_count);

  auto derived_words = apply_grounding (words, var_cols, var_values);
  return derived_words;
}

void load_prop_rules (const char *path) {
  ifstream db (path);
  if (!db) {
    printf ("Rules database not found. Can you ensure that '%s' "
            "exists in the current working directory?\n",
            path);
    exit (1);
  }
  int id, count = 0;
  string input, output;
  while (db >> id >> input >> output) {
    string key = to_string (id) + input;
    io_prop_rules.insert ({key, output});
    count++;
  }

  printf ("Loaded %d rules into %ld buckets\n", count,
          io_prop_rules.bucket_count ());
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

void prop_with_int_diff (int equation_id, vector<string *> words) {
  vector<int> underived_indices;
  int words_count = words.size ();
  vector<int64_t> word_diffs (words_count);
  for (int i = 0; i < words_count; i++) {
    int64_t int_diff = _int_diff ((char *) words[i]->c_str ());
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
    underived_words.push_back (*words[underived_indices[i]]);
  auto derived_words = derive_words (underived_words, constant);

  for (int i = 0; i < underived_count; i++) {
    auto index = underived_indices[i];
    string new_word = derived_words[i];
    *words[index] = new_word;
  }
}

void Propagator::prop_addition_weakly () {
  auto get_value = [] (char diff_char, int block) {
    if (diff_char == 'u')
      return block == 0 ? '1' : '0';
    else if (diff_char == 'n')
      return block == 0 ? '0' : '1';
    else if (diff_char == '0')
      return '0';
    else if (diff_char == '1')
      return '1';
    else if (diff_char == '3')
      return block == 1 ? '0' : '?';
    else if (diff_char == '5')
      return block == 0 ? '0' : '?';
    else if (diff_char == 'A')
      return block == 0 ? '1' : '?';
    else if (diff_char == 'C')
      return block == 1 ? '1' : '?';
    else
      return '?';
  };

  auto get_id = [] (Word *word, int j, int block) {
    return block == 0 ? word->ids_f[j] : word->ids_g[j];
  };

  for (int block = 0; block < 1; block++) {
    for (int i = 0; i < order; i++) {
      auto &step_operations = operations[i];
      vector<tuple<Word **, Word **, int, int>> add_operations = {
          {step_operations.add_t.inputs, step_operations.add_t.carries, 5,
           2},
          {step_operations.add_e.inputs, step_operations.add_e.carries, 2,
           1},
          {step_operations.add_a.inputs, step_operations.add_a.carries, 3,
           2}};
      if (i >= 16)
        add_operations.push_back ({step_operations.add_w.inputs,
                                   step_operations.add_w.carries, 4, 2});

      for (auto &operation : add_operations) {
        auto &inputs = get<0> (operation);
        auto &carries = get<1> (operation);
        auto &inputs_count = get<2> (operation);
        auto &carries_count = get<3> (operation);

        for (int j = 0; j < 32; j++) {
          int count_1 = 0, count_0 = 0, count_u = 0;

          // Process the addends
          vector<char> addends;
          vector<int> addend_ids;
          int r[] = {-1, -1};
          for (int k = 0; k < inputs_count; k++) {
            addends.push_back (inputs[k]->chars[31 - j]);
            addend_ids.push_back (get_id (inputs[k], 31 - j, block));
          }

          // Current column's addends include T-2 and t-1
          if (j - 1 >= 0) {
            addends.push_back (carries[0]->chars[31 - j + 1]);
            r[0] = get_id (carries[0], 31 - j, block);
            addend_ids.push_back (get_id (carries[0], 31 - j + 1, block));
          }
          if (j - 2 >= 0 && carries_count > 1) {
            addends.push_back (carries[1]->chars[31 - j + 2]);
            r[1] = get_id (carries[1], 31 - j, block);
            addend_ids.push_back (get_id (carries[1], 31 - j + 2, block));
          }
          int addends_count = addends.size ();

          // Count the 3 types of addends
          vector<uint32_t> undefined_ids, one_ids, zero_ids;
          for (int k = 0; k < addends_count; k++) {
            // Get the value for the block
            auto value = get_value (addends[k], block);
            if (value == '?') {
              count_u++;
              undefined_ids.push_back (addend_ids[k]);
            } else if (value == '1') {
              count_1++;
              one_ids.push_back (addend_ids[k]);
            } else if (value == '0') {
              count_0++;
              zero_ids.push_back (addend_ids[k]);
            }
          }
          assert (count_0 + count_1 + count_u == addends_count);

          if (!(addends_count >= 5 && addends_count <= 7))
            continue;

          // printf ("Debug: carries %d: %d %d\n", j, r[0], r[1]);
          bool has_high_carry = r[1] != -1, has_low_carry = r[0] != -1;
          bool is_high_carry_undef =
                   has_high_carry &&
                   partial_assignment.get (r[1]) == LIT_UNDEF,
               is_low_carry_undef =
                   has_low_carry &&
                   partial_assignment.get (r[0]) == LIT_UNDEF;

          if (has_high_carry && is_high_carry_undef) {
            // Carry propagation: r1 = 1 if input >= 4
            if (count_1 >= 4) {
              // vector<int> reason_clause;
              // for (auto &id : one_ids) {
              //   if (partial_assignment.get (id) == LIT_UNDEF)
              //     return;
              //   reason_clause.push_back (-id);
              // }
              // reason_clause.push_back (r[1]);

              // propagation_lits.push_back (r[1]);
              // reason_clauses.insert ({r[1], reason_clause});

              // printf ("Debug: inserted reason clause for %d: ", r[1]);
              // for (auto &lit : reason_clause)
              //   printf ("%d ", partial_assignment.get (abs (lit)));
              // printf ("\n");
              decision_lits.push_back (r[1]);
              return;
            }
            // Carry propagation: r1 = 0 if input < 4
            if (count_0 >= 4) {
              // propagation_lits.push_back (-r[1]);
              // vector<int> reason_clause;
              // for (auto &id : zero_ids)
              //   reason_clause.push_back (-id);
              // reason_clauses.insert ({-r[1], reason_clause});
              decision_lits.push_back (-r[1]);
              return;
            }
          }

          if (has_low_carry && is_low_carry_undef) {
            // Carry propagation: r0 = 1 if input >= 6 or 2 <= input < 4
            if (count_1 >= 6 || (2 <= count_1 && count_1 + count_u < 4)) {
              // propagation_lits.push_back (r[0]);
              // vector<int> reason_clause;
              // for (auto &id : one_ids)
              //   reason_clause.push_back (id);
              // for (auto &id : zero_ids)
              //   reason_clause.push_back (-id);
              // reason_clauses.insert ({r[0], reason_clause});
              decision_lits.push_back (r[0]);
              return;
            }
            // Carry propagation: r0 = 0 if input < 2 or 4 <= input < 6
            if (count_0 >= 6 || (4 <= count_1 && count_1 + count_u < 6)) {
              // propagation_lits.push_back (-r[0]);
              // vector<int> reason_clause;
              // for (auto &id : one_ids)
              //   reason_clause.push_back (id);
              // for (auto &id : zero_ids)
              //   reason_clause.push_back (-id);
              // reason_clauses.insert ({-r[0], reason_clause});
              decision_lits.push_back (-r[0]);
              return;
            }
          }

          if (has_high_carry && !is_high_carry_undef) {
            bool is_r1_true = partial_assignment.get (r[1]) == LIT_TRUE;
            // Addend propagation: input <= 3 if r1 = 0
            if (!is_r1_true && count_1 == 3)
              for (int k = 0; k < count_u; k++) {
                // propagation_lits.push_back (-undefined_ids[k]);
                // vector<int> reason_clause;
                // reason_clause.push_back (-undefined_ids[k]);
                // reason_clause.push_back (-r[1]);
                // reason_clauses.insert ({-undefined_ids[k],
                // reason_clause});
                decision_lits.push_back (-undefined_ids[k]);
                return;
              }
            // Addend propagation: input >= 4 if r1 = 1
            else if (is_r1_true && count_1 + count_u == 4)
              for (int k = 0; k < count_u; k++) {
                // propagation_lits.push_back (undefined_ids[k]);
                // vector<int> reason_clause;
                // reason_clause.push_back (undefined_ids[k]);
                // reason_clause.push_back (r[1]);
                // reason_clauses.insert ({undefined_ids[k],
                // reason_clause});
                decision_lits.push_back (undefined_ids[k]);
                return;
              }
          }
        }
      }
    }
  }
}

// Works for addition hardcoded up to 3 carries
pair<string, string> otf_add_propagate (string inputs, string outputs) {
  auto add = [] (vector<int> inputs, int *outputs) {
    int sum = accumulate (inputs.begin (), inputs.end (), 0);
    outputs[0] = sum & 1;
    outputs[1] = sum >> 1 & 1;
    outputs[2] = sum >> 2 & 1;
  };

  auto conforms_to = [] (char c1, char c2) {
    auto c1_chars = symbols[c1], c2_chars = symbols[c2];
    for (auto &c : c1_chars)
      if (find (c2_chars.begin (), c2_chars.end (), c) == c2_chars.end ())
        return false;
    return true;
  };

  int n = inputs.size (), m = outputs.size ();
  vector<vector<char>> iterables_list;
  for (auto &input : inputs) {
    auto it = symbols.find (input);
    if (it != symbols.end ())
      iterables_list.push_back (it->second);
  }

  set<char> possibilities[n + m];
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

    int outputs_f[3], outputs_g[3];
    add (inputs_f, outputs_f);
    add (inputs_g, outputs_g);

    string actual_outputs;
    bool skip = false;
    for (int i = 0; i < m; i++) {
      if (outputs_f[i] == 1 && outputs_g[i] == 1)
        actual_outputs += '1';
      else if (outputs_f[i] == 1 && outputs_g[i] == 0)
        actual_outputs += 'u';
      else if (outputs_f[i] == 0 && outputs_g[i] == 1)
        actual_outputs += 'n';
      else
        actual_outputs += '0';

      // Output must conform to that given
      if (!conforms_to (actual_outputs[i], outputs[m - 1 - i])) {
        skip = true;
        break;
      }
    }
    if (skip)
      continue;
    for (int i = 0; i < n; i++)
      possibilities[i].insert (combo[i]);
    for (int i = 0; i < m; i++)
      possibilities[n + i].insert (actual_outputs[m - 1 - i]);
  }

  auto gc_from_set = [] (set<char> &set) {
    // assert (set.size () > 0);
    for (auto &entry : symbols_set)
      if (set == entry.second)
        return entry.first;
    return '#';
  };

  string final_inputs, final_outputs;
  for (int i = 0; i < n; i++)
    final_inputs += gc_from_set (possibilities[i]);
  for (int i = 0; i < m; i++)
    final_outputs += gc_from_set (possibilities[n + i]);

  return {final_inputs, final_outputs};
}

void otf_add_propagate (TwoBit &two_bit, vector<Word *> inputs,
                        vector<Word *> carries, vector<Word *> outputs) {
  for (int i = 31; i >= 0; i--) {
    string inputs_col, outputs_col;

    for (auto &word : inputs)
      inputs_col += word->chars[i];
    if (i + 1 <= 31)
      inputs_col += carries[0]->chars[i + 1];
    if (carries.size () == 2 && i + 2 <= 31)
      inputs_col += carries[1]->chars[i + 2];

    for (auto &word : outputs)
      outputs_col += word->chars[i];

    int n = inputs_col.size (), m = outputs_col.size ();

    auto result_it =
        add_prop_rules.find ({inputs_col, outputs_col.back ()});
    pair<string, string> propagation;
    if (result_it == add_prop_rules.end ()) {
      propagation = otf_add_propagate (inputs_col, outputs_col);
      // Cache the result
      add_prop_rules[{propagation.first, propagation.second.back ()}] =
          propagation;
    } else {
      // Use the cached result
      propagation = result_it->second;
    }

    vector<uint32_t> diff_ids;
    vector<string> names (n + m);
    for (auto &word : inputs)
      diff_ids.push_back (word->diff_ids[i]);
    if (i + 1 <= 31)
      diff_ids.push_back (0);
    if (carries.size () == 2 && i + 2 <= 31)
      diff_ids.push_back (0);

    for (auto &word : outputs)
      if (word == outputs.back ())
        diff_ids.push_back (word->diff_ids[i]);
      else
        diff_ids.push_back (0);
    assert (int (diff_ids.size ()) == n + m);

    otf_derive_add_two_bit_equations (two_bit, propagation.first,
                                      propagation.second, diff_ids, names,
                                      inputs, carries, outputs, i);

    // int carries_count = carries.size ();
    // for (int j = 0; j < n - carries_count; j++)
    //   inputs[j]->chars[i] = propagation.first[j];
    // for (int j = 0; j < carries_count; j++)
    //   carries[j]->chars[i] = propagation.first[n - carries_count + j];
    // for (int j = 0; j < m; j++)
    //   outputs[j]->chars[i] = propagation.second[j];

    // cout << "Input:  " << i << " " << inputs_col << " " << outputs_col
    //      << endl;
    // cout << "Output: " << i << " ";
    // for (int j = 0; j < n; j++)
    //   cout << propagation.first[j];
    // cout << " ";
    // for (int j = 0; j < m; j++)
    //   cout << propagation.second[j];
    // cout << endl;
  }
}

} // namespace SHA256