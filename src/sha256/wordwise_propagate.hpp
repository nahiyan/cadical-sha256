#ifndef _sha256_wordwise_propagate_hpp_INCLUDED
#define _sha256_wordwise_propagate_hpp_INCLUDED

#include "util.hpp"
#include <cstdint>
#include <queue>
#include <string>
#include <vector>

// #define WP_VARS_LIMIT 10
// The limit for the number of variables in a column
#define WP_COL_SIZE_LIMIT 6

using namespace std;

namespace SHA256 {
// Note: Rest is little-endian for simplicity
// Note: Cond. words have big-endian ordering

// A Boolean variable describing the modular difference
struct WWVar {
  string *cond_word_ptr;
  char *cond_ptr;
  int8_t value = -1;

  // Relevant for variables related to any in {?, 7, E}
  bool is_low_q7e_var = false;
  int high_q7e_var_index = -1;

  // Relevant for carry variables
  bool is_low_carry = false;
  bool is_high_carry = false;
};
struct WWCol {
  vector<WWVar> vars;
  // GF(2) sum of all the variables
  int8_t sum;
  // Index of the carry var. 1 col. back.
  int low_carry_index = -1;
  // Index of the carry var. 2 cols. back
  int high_carry_index = -1;
};
// Variables organized by columns
typedef vector<WWCol> WWCols;
class WWPropagate {
public:
  static void init_cols (WWCols &cols, long cols_count,
                         long normalized_sum) {
    cols.resize (cols_count);
    for (int i = 0; i < cols.size (); i++)
      cols[i].sum = normalized_sum >> i & 1;
  }
  static vector<string> propagate (vector<string> cond_words, int64_t sum,
                                   bool brute_force_on = true) {
    assert (!cond_words.empty ());
    // Normalize the modular addition sum
    int64_t normalized_sum = sum;
    for (auto &word : cond_words)
      normalized_sum = normalize_sum (normalized_sum, word);

    // Derive the regular variables and carries
    WWCols cols;
    init_cols (cols, cond_words[0].size (), normalized_sum);
    derive_reg_vars (cond_words, &cols);
    derive_carr_vars (&cols);

    // Derive vars in the unit columns (i.e. columns with only 1 variable)
    for (int iters = 1; iters > 0; iters--) {
      for (long col_index = 0; col_index < cols.size (); col_index++) {
        WWCol &col = cols[col_index];
        assert (col.vars.size () <= WP_COL_SIZE_LIMIT);
        int unknown_vars = 0, known_vars_sum = 0;
        for (auto &var : col.vars) {
          unknown_vars += var.value == -1;
          known_vars_sum += var.value == -1 ? 0 : var.value;
        }
        known_vars_sum &= 1;
        // We aim for a unit column
        if (unknown_vars != 1)
          continue;
        for (auto &var : col.vars) {
          if (var.value != -1)
            continue;
          var.value = col.sum ^ known_vars_sum;
          assert ((var.value ^ known_vars_sum) == col.sum);
          if (var.is_low_q7e_var && var.high_q7e_var_index != -1 &&
              var.value == 1) {
            cols[col_index + 1].vars[var.high_q7e_var_index].value = 0;
            iters = 2;
          }
          break;
        }
      }
    }

    if (brute_force_on)
      brute_force (&cols);

    // Propagate the conditions from the vars.
    for (int iters = 1; iters > 0; iters--) {
      for (auto &col : cols) {
        for (WWVar &var : col.vars) {
          if (var.cond_ptr == nullptr)
            continue;
          char &cond = *var.cond_ptr;
          int8_t value = var.value;
          if (cond == 'x') {
            if (value == -1)
              continue;
            cond = value == 1 ? 'u' : 'n';
          } else if (is_in (cond, {'3', '5', 'A', 'B', 'C', 'D'})) {
            if (value == -1)
              continue;
            switch (cond) {
            case '3':
              cond = value == 0 ? '0' : 'u';
              break;
            case '5':
              cond = value == 0 ? 'n' : '0';
              break;
            case 'A':
              cond = value == 0 ? '1' : 'u';
              break;
            case 'B':
              cond = value == 0 ? '-' : 'u';
              break;
            case 'C':
              cond = value == 0 ? 'n' : '1';
              break;
            case 'D':
              cond = value == 0 ? 'n' : '-';
              break;
            }
          } else if (is_in (cond, {'7', 'E', '?'})) {
            if (value == -1)
              continue;

            if (var.is_low_q7e_var) {
              cond = value == 0 ? 'x'
                                : (cond == '7'   ? '0'
                                   : cond == 'E' ? '1'
                                                 : '-');
              // See if 'x' can be broken down in another iteration
              if (cond == 'x')
                iters = 2;
            } else {
              // Assuming that the lower variable has been analyzed first
              cond = value == 1 ? 'u' : cond;
            }
          }
        }
      }
    }

    return cond_words;
  }

  // Breadth-first brute force
  static void brute_force (WWCols *cols_, bool limit = false) {
    WWCols &cols = *cols_;
    assert (!cols.empty ());
    int cols_count = cols.size ();

    // Process the columns
    for (int iters = 1; iters > 0; !limit ? iters-- : iters = 0) {
      for (int col_index = 0; col_index < cols_count; col_index++) {
        // Current col.
        WWCol &col = cols[col_index];
        assert (col.vars.size () <= WP_COL_SIZE_LIMIT);

        // Get the indices of the unknown vars.
        vector<int> unknown_var_indices;
        int known_var_sum = 0;
        for (long i = 0; i < col.vars.size (); i++) {
          if (col.vars[i].value == -1) {
            unknown_var_indices.push_back (i);
            continue;
          }
          known_var_sum += col.vars[i].value;
        }
        long unknown_var_count = unknown_var_indices.size ();

        // Enumerate the solutions
        set<int8_t> possible_var_values[col.vars.size ()];
        set<int8_t> possible_low_carry_values, possible_high_carry_values;
        vector<int> solutions;
        for (int i = 0;
             i < pow (2, unknown_var_count) && unknown_var_count > 0; i++) {
          int combination_sum = 0;
          for (int j = 0; j < unknown_var_count; j++)
            combination_sum += i >> j & 1;

          int sum = combination_sum + known_var_sum;
          if ((sum & 1) != col.sum)
            continue;

          // Is the low carry known?
          if (col.low_carry_index != -1) {
            assert (col_index + 1 < cols_count);
            int8_t &low_carry =
                cols[col_index + 1].vars[col.low_carry_index].value;
            if (low_carry != -1 && low_carry != (sum >> 1 & 1))
              continue;
          }
          // Is the high carry known?
          if (col.high_carry_index != -1) {
            assert (col_index + 2 < cols_count);
            int8_t &high_carry =
                cols[col_index + 2].vars[col.high_carry_index].value;
            if (high_carry != -1 && high_carry != (sum >> 2 & 1))
              continue;
          }

          solutions.push_back (i);
          for (int j = 0; j < unknown_var_count; j++) {
            int index = unknown_var_indices[j];
            possible_var_values[index].insert (i >> j & 1);
          }
          possible_low_carry_values.insert (sum >> 1 & 1);
          possible_high_carry_values.insert (sum >> 2 & 1);
        }

        // Catch contradictions
        if (solutions.empty () && unknown_var_count > 0)
          return;

        // Derive the reg. vars.
        for (long i = 0; i < col.vars.size (); i++) {
          // int index = unknown_var_indices[i];
          WWVar &var = col.vars[i];
          if (col.vars[i].value == -1) {
            assert (!possible_var_values[i].empty ());
            if (possible_var_values[i].size () == 1) {
              iters = 2;
              var.value = *possible_var_values[i].begin ();
            }
          }

          // Vars. in {?, 7, E} can't be (1, 1)
          if (var.is_low_q7e_var && var.value == 1 &&
              var.high_q7e_var_index != -1) {
            assert (col_index + 1 < cols_count);
            cols[col_index + 1].vars[var.high_q7e_var_index].value = 0;
            iters =
                cols[col_index + 1].vars[var.high_q7e_var_index].value == -1
                    ? 2
                    : 0;
          }
        }

        // Derive the carries
        if (possible_low_carry_values.size () == 1 &&
            col_index + 1 < cols_count) {
          assert (!possible_low_carry_values.empty ());
          int low_carry_index = col.low_carry_index;
          if (*possible_low_carry_values.begin () == 1)
            assert (low_carry_index != -1);
          if (low_carry_index != -1) {
            iters = cols[col_index + 1].vars[low_carry_index].value == -1
                        ? 2
                        : iters;
            cols[col_index + 1].vars[low_carry_index].value =
                *possible_low_carry_values.begin ();
          }
        }
        if (possible_high_carry_values.size () == 1 &&
            col_index + 2 < cols_count) {
          assert (!possible_high_carry_values.empty ());
          int high_carry_index = col.high_carry_index;
          if (*possible_high_carry_values.begin () == 1)
            assert (high_carry_index != -1);
          if (high_carry_index != -1) {
            iters = cols[col_index + 2].vars[high_carry_index].value == -1
                        ? 2
                        : iters;
            cols[col_index + 2].vars[high_carry_index].value =
                *possible_high_carry_values.begin ();
          }
        }
      }
    }
  }

  // Normalize the sum of modular addition based on the condition word
  // This is to ensure that no negative differences occur
  // Moreover, the condition 'u' that influences the sum is
  // neutralized.
  static int64_t normalize_sum (int64_t sum, string cond_word,
                                vector<char> target_conds = {
                                    'x', 'n', '5', 'C', 'D', '?'}) {
    size_t n = cond_word.size ();
    for (size_t i = 0; i < n; i++) {
      char cond = cond_word[n - 1 - i];
      if (is_in (cond, target_conds))
        sum += pow (2, i);

      // Remove grounded conditions affecting the sum
      if (cond == 'u')
        sum -= pow (2, i);
    }

    return e_mod (sum, pow (2, n));
  }

  // Derive the regular variables.
  // Regular variables are ones related directly to the conditions.
  static void derive_reg_vars (vector<string> &cond_words, WWCols *cols_) {
    assert (!cond_words.empty ());
    WWCols &cols = *cols_;
    long cols_count = cols.size ();

    // Note: x is the condition index
    // Note: col is the column index
    for (int col_index = 0; col_index < cols_count; col_index++) {
      bool has_next_col = col_index + 1 < cols_count;
      for (auto &cond_word : cond_words) {
        char &cond = cond_word[cols_count - 1 - col_index];
        if (cond == 'x' && has_next_col) {
          cols[col_index + 1].vars.push_back ({&cond_word, &cond, -1});
        } else if (is_in (cond, {'?', '7', 'E'})) {
          WWVar var{&cond_word, &cond, -1};
          var.value = -1;
          var.is_low_q7e_var = true;

          // Add the higher variable if there's space
          if (has_next_col) {
            cols[col_index + 1].vars.push_back ({&cond_word, &cond, -1});
            var.high_q7e_var_index = cols[col_index + 1].vars.size () - 1;
          }
          cols[col_index].vars.push_back (var);
        } else if (is_in (cond, {'3', '5', 'A', 'B', 'C', 'D'})) {
          cols[col_index].vars.push_back ({&cond_word, &cond, -1});
        }
      }
    }
  }

  // Derive the carry variables.
  static void derive_carr_vars (WWCols *cols_) {
    WWCols &cols = *cols_;
    for (long col_index = 0; col_index < cols.size (); col_index++) {
      // Current col.
      WWCol &col = cols[col_index];
      // Variables in the current column
      vector<WWVar> &vars = cols[col_index].vars;
      assert (vars.size () <= WP_COL_SIZE_LIMIT);
      if (vars.empty ()) // Skip empty columns
        continue;

      bool has_next_col = col_index + 1 < cols.size ();
      bool has_next_next_col = col_index + 2 < cols.size ();

      // Check if any combination can induce a carry
      bool has_low_carry = false, has_high_carry = false;
      for (int i = 0; i < pow (2, vars.size ()); i++) {
        int sum = 0;
        for (int j = 0; j < vars.size (); j++) {
          sum += i >> j & 1;
        }
        if ((sum & 1) != col.sum)
          continue;
        has_low_carry |= (sum >> 1 & 1) == 1;
        has_high_carry |= (sum >> 2 & 1) == 1;
      }
      // Low carry
      if (has_low_carry && has_next_col) {
        WWVar var{nullptr, nullptr, -1};
        var.is_low_carry = true;
        col.low_carry_index = cols[col_index + 1].vars.size ();
        cols[col_index + 1].vars.push_back (var);
      }
      // High carry
      if (has_high_carry && has_next_next_col) {
        WWVar var{nullptr, nullptr, -1};
        var.is_high_carry = true;
        col.high_carry_index = cols[col_index + 2].vars.size ();
        cols[col_index + 2].vars.push_back (var);
      }
    }
  }

  static void print (vector<string> *cond_words_, WWCols cols) {
    if (cond_words_ != nullptr) {
      auto &cond_words = *cond_words_;
      for (auto &cond_word : cond_words)
        printf ("%s\n", cond_word.c_str ());
    }

    for (int i = 0; i < WP_COL_SIZE_LIMIT; i++) {
      string line;
      for (int j = cols.size () - 1; j >= 0; j--) {
        auto &col = cols[j];
        if (i < col.vars.size ()) {
          auto &var = col.vars[i];
          line += var.value == -1
                      ? (var.is_low_carry || var.is_high_carry ? 'c' : 'v')
                      : (var.value == 1 ? '1' : '0');
        } else {
          line += " ";
        }
      }
      bool found_vars = false;
      for (auto &c : line)
        found_vars |= c != ' ';
      if (found_vars)
        printf ("%s\n", line.c_str ());
    }

    for (int j = cols.size () - 1; j >= 0; j--)
      printf ("%d", cols[j].sum);
    printf ("\n");
  }
};
} // namespace SHA256

#endif