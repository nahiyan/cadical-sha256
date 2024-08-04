#ifndef _sha256_wordwise_propagate_hpp_INCLUDED
#define _sha256_wordwise_propagate_hpp_INCLUDED

#include "util.hpp"
#include <cstdint>
#include <string>
#include <vector>

#define WP_VARS_LIMIT 10
// The limit for the number of variables in a column
#define WP_COL_SIZE_LIMIT 4

using namespace std;

namespace SHA256 {
// Note: Cond. words have big-endian ordering
// Note: Rest is little-endian for simplicity
struct WWVar {
  string *cond_word_ptr;
  char *cond_ptr;
  int8_t value = -1;

  // Relevant for variables related to any in {?, 7, E}
  bool is_lower_var = false;
  int higher_var_index = -1;
};
typedef vector<vector<WWVar>> VarsColwise;
class WWSubproblem {
  // The word size in a subproblem is the width of the subproblem
  vector<string> word_conds;
  int64_t sum;
  VarsColwise vars_colwise;
};
class WWPropagate {
public:
  static vector<string> propagate (vector<string> cond_words, int64_t sum,
                                   int limit = -1) {
    // TODO: Implement limit of number of conditions to propagate. E.g.
    // limit = 1 means that it'd stop after 1 condition has been propagated.

    // Normalize the modular addition sum
    int64_t normalized_sum = sum;
    for (auto &word : cond_words)
      normalized_sum = normalize_sum (normalized_sum, word);

    // Derive the regular variables and carries
    VarsColwise vars_colwise;
    derive_reg_vars (cond_words, &vars_colwise);
    derive_carr_vars (&vars_colwise, normalized_sum);

    // Derive vars in the unit columns
    for (int iters = 1; iters > 0; iters--) {
      for (long col_index = 0; col_index < vars_colwise.size ();
           col_index++) {
        vector<WWVar> &col = vars_colwise[col_index];
        int unknown_vars = 0, known_sum = 0;
        for (auto &var : col) {
          unknown_vars += var.value == -1;
          known_sum += var.value == -1 ? 0 : var.value;
        }
        known_sum &= 1;
        if (unknown_vars != 1)
          continue;
        for (auto &var : col) {
          if (var.value != -1)
            continue;
          var.value = known_sum == 1 ? 0 : 1;
          if (*var.cond_ptr == '?' && var.higher_var_index != -1 &&
              var.value == 1) {
            vars_colwise[col_index + 1][var.higher_var_index].value = 0;
            iters = 2;
          }
          break;
        }
      }
    }

    int i = -1;
    for (auto &col : vars_colwise) {
      i++;
      printf ("%d: ", i);
      for (auto &var : col)
        printf ("%c", var.value == -1
                          ? (var.cond_ptr == nullptr ? 'c' : 'v')
                          : (var.value == 0   ? '0'
                             : var.value == 1 ? '1'
                                              : '?'));
      printf ("\n");
    }

    // TODO: Derive vars through breadth-first brute force

    // Propagate the conditions from the vars
    for (int iters = 1; iters > 0; iters--) {
      for (auto &col : vars_colwise) {
        for (WWVar &var : col) {
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
              cond = value == '0' ? '0' : 'u';
              break;
            case '5':
              cond = value == '0' ? 'n' : '0';
              break;
            case 'A':
              cond = value == '0' ? '1' : 'u';
              break;
            case 'B':
              cond = value == '0' ? '-' : 'u';
              break;
            case 'C':
              cond = value == '0' ? 'n' : '1';
              break;
            case 'D':
              cond = value == '0' ? 'n' : '-';
              break;
            }
          } else if (is_in (cond, {'7', 'E', '?'})) {
            if (value == -1)
              continue;

            if (var.is_lower_var) {
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
  static void derive_reg_vars (vector<string> &cond_words,
                               VarsColwise *vars_colwise_) {
    assert (!cond_words.empty ());
    long cols_count = cond_words[0].size ();
    VarsColwise &vars_colwise = *vars_colwise_;
    vars_colwise.resize (cols_count);

    // Note: x is the condition index
    // Note: col is the column index
    for (int col_index = 0; col_index < cols_count; col_index++) {
      bool has_next_col = col_index + 1 < cols_count;
      for (auto &cond_word : cond_words) {
        char &cond = cond_word[cols_count - 1 - col_index];
        if (cond == 'x' && has_next_col) {
          vars_colwise[col_index + 1].push_back ({&cond_word, &cond, -1});
        } else if (is_in (cond, {'?', '7', 'E'})) {
          WWVar var{&cond_word, &cond, -1};
          var.is_lower_var = true;

          // Add the higher variable if there's space
          if (has_next_col) {
            vars_colwise[col_index + 1].push_back ({&cond_word, &cond, -1});
            var.higher_var_index = vars_colwise[col_index + 1].size () - 1;
          }
          vars_colwise[col_index].push_back (var);
        } else if (is_in (cond, {'3', '5', 'A', 'B', 'C', 'D'})) {
          vars_colwise[col_index].push_back ({&cond_word, &cond, -1});
        }
      }
    }
  }

  // Derive the carry variables.
  static void derive_carr_vars (VarsColwise *vars_colwise_,
                                int64_t normalized_sum) {
    VarsColwise &vars_colwise = *vars_colwise_;
    for (long col_index = 0; col_index < vars_colwise.size ();
         col_index++) {
      // Variables in the current column
      auto vars = vars_colwise[col_index];
      assert (vars.size () <= 4);
      if (vars.empty ()) // Skip empty columns
        continue;

      int8_t col_sum = normalized_sum >> col_index & 1;
      bool has_next_col = col_index + 1 < vars_colwise.size ();
      bool has_next_next_col = col_index + 2 < vars_colwise.size ();

      // Check if any combination can induce a carry
      bool has_low_carry = false;
      bool has_high_carry = false;
      for (int j = 0; j < vars.size (); j++) {
        if ((j & 1) != col_sum)
          continue;
        has_low_carry |= (j >> 1 & 1) == 1;
        has_high_carry |= (j >> 2 & 1) == 1;
      }
      // Low carry
      if (has_low_carry && has_next_col)
        vars_colwise[col_index + 1].push_back ({nullptr, nullptr, -1});
      // High carry
      if (has_high_carry && has_next_next_col)
        vars_colwise[col_index + 2].push_back ({nullptr, nullptr, -1});
    }
  }
};
} // namespace SHA256

#endif