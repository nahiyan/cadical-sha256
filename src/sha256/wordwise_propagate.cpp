#include "wordwise_propagate.hpp"
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
// // * Important: The wordwise propagation engine uses big-endian ordering
// struct ValueWithOrder {
//   char value;
//   uint8_t order; // Order will be 31 max and 8 bits can hold 0-255
// };

// int64_t adjust_constant (string word, int64_t constant,
//                          vector<char> adjustable_gcs) {
//   if (adjustable_gcs.size () == 0)
//     adjustable_gcs = {'x', 'n', '5', 'C', 'D', '?'};

//   size_t n = word.size ();
//   for (size_t i = 0; i < n; i++) {
//     char gc = word[n - 1 - i];
//     if (is_in (gc, adjustable_gcs))
//       constant += pow (2, i);
//   }

//   return e_mod (constant, pow (2, n));
// }

// bool is_congruent (int64_t a, int64_t b, int64_t m) {
//   return (a - b) % m == 0;
// }

// tuple<vector<ValueWithOrder>, int64_t>
// process_var_cols (vector<string> var_cols) {
//   vector<ValueWithOrder> vars;
//   int64_t const_value = 0;
//   int cols_count = var_cols.size ();
//   for (int i = 0; i < cols_count; i++) {
//     auto &col = var_cols[i];
//     int rows_count = col.size ();
//     for (int j = 0; j < rows_count; j++) {
//       auto &var = col[j];
//       if (var == 'v')
//         vars.push_back ({-1, uint8_t (i)});
//       else
//         const_value += (var == '1' ? 1 : 0) * int64_t (pow (2, i));
//     }
//   }

//   return {vars, const_value};
// }

// bool _can_overflow (vector<string> var_cols, vector<uint8_t> bits) {
//   auto count_vars = [] (vector<string> cols) {
//     int vars_count = 0;
//     for (auto &col : cols) {
//       for (auto &c : col) {
//         if (c != 'v')
//           continue;
//         vars_count++;
//       }
//     }

//     return vars_count;
//   };

//   int bits_count = bits.size ();
//   int64_t value = 0;
//   int64_t max_value = (int64_t (1) << bits_count) - 1;

//   // Trivial overflow check using the last column in the stash. If the
//   last
//   // column has 1 variable, bit under the column is 1, and there is no
//   high
//   // carry affecting this column, it can't overflow. This is because the
//   // addends can never sum up to 2 and induce a carry.
//   int last_index = var_cols.size () - 1;
//   if (var_cols[last_index].size () == 1 && last_index - 2 >= 0 &&
//       var_cols[last_index - 2].size () < 4 && bits[last_index] == 1)
//     return false;

//   // Trick to skip the check if there are too many variables
//   if (count_vars (var_cols) > WP_VARS_LIMIT)
//     return true;

//   // Calculate the value
//   for (int i = 0; i < bits_count; i++)
//     value += bits[i] * int64_t (pow (2, i));

//   auto var_cols_processed = process_var_cols (var_cols);
//   vector<ValueWithOrder> vars = get<0> (var_cols_processed);
//   int64_t const_value = get<1> (var_cols_processed);

//   int64_t m = pow (2, bits_count);
//   int vars_count = vars.size ();
//   for (int64_t i = pow (2, vars_count); i >= 0; i--) {
//     int64_t candidate_value = const_value;
//     for (int j = 0; j < vars_count; j++) {
//       auto &var = vars[j];
//       candidate_value += (i >> j & 1) * int64_t (pow (2, var.order));
//     }
//     if (candidate_value <= max_value)
//       continue;
//     if (is_congruent (candidate_value, value, m))
//       return true;
//   }

//   return false;
// }

// vector<string> gen_vars (vector<string> words) {
//   int cols_count = words[0].size ();
//   vector<string> var_cols (cols_count);

//   int words_count = words.size ();
//   for (int i = 0; i < words_count; i++) {
//     for (int j = cols_count - 1; j >= 0; j--) {
//       char gc = words[i][j];
//       bool is_msb = j == 0;
//       if (gc == 'x' && !is_msb) {
//         var_cols[j - 1].push_back ('v');
//       } else if (is_in (gc, {'?', '7', 'E'})) {
//         var_cols[j].push_back ('v');
//         if (!is_msb)
//           var_cols[j - 1].push_back ('v');
//       } else if (is_in (gc, {'3', '5', 'A', 'B', 'C', 'D'})) {
//         var_cols[j].push_back ('v');
//       }
//     }
//   }

//   // Deal with the constants but treat them as derived variables
//   for (int i = cols_count - 1; i >= 0; i--) {
//     int sum = 0;
//     for (int j = 0; j < words_count; j++)
//       sum += words[j][i] == 'u' ? 1 : 0;

//     assert (sum >= 0 && sum <= 2);
//     if (sum == 2 && i - 1 >= 0)
//       var_cols[i - 1].push_back ('1');
//     else if (sum == 1)
//       var_cols[i].push_back ('1');
//   }

//   return var_cols;
// }

// string brute_force (vector<string> var_cols, int64_t constant,
//                     int64_t min_gt, bool can_overflow) {
//   auto var_cols_processed = process_var_cols (var_cols);
//   vector<ValueWithOrder> vars = get<0> (var_cols_processed);
//   int64_t const_value = get<1> (var_cols_processed);
//   int vars_count = vars.size ();
//   vector<vector<int>> solutions;
//   for (int64_t i = 0; i < pow (2, vars_count); i++) {
//     int64_t sum = const_value;
//     vector<int> values (vars_count);
//     for (int j = 0; j < vars_count; j++) {
//       values[j] = i >> j & 1;
//       sum += values[j] * int64_t (pow (2, vars[j].order));
//     }
//     if (can_overflow) {
//       sum = e_mod (sum, int64_t (pow (2, var_cols.size ())));
//       if (sum != constant)
//         continue;
//     }
//     if (min_gt == -1 && sum != constant)
//       continue;
//     if (min_gt != -1 && sum <= min_gt)
//       continue;
//     solutions.push_back (values);
//   }

//   int sols_count = solutions.size ();
//   vector<char> pattern (vars_count);
//   for (int i = 0; i < sols_count; i++) {
//     auto solution = solutions[i];
//     for (int j = 0; j < vars_count; j++) {
//       if (pattern[j] == 'v')
//         continue;
//       if (pattern[j] != '0' && pattern[j] != '1' && pattern[j] != 'v')
//         pattern[j] = solution[i] == 1 ? '1' : '0';

//       bool matching = (pattern[j] == '1' && solution[j] == 1) ||
//                       (pattern[j] == '0' && solution[j] == 0);
//       if (!matching)
//         pattern[j] = 'v';
//     }
//   }

//   string pattern_ (pattern.begin (), pattern.end ());
//   return pattern_;
// }

// vector<string> apply_grounding (vector<string> words,
//                                 vector<string> var_cols,
//                                 vector<char> var_values) {
//   // Remove constants from columns
//   int i = 0;
//   for (auto &col : var_cols) {
//     string new_col;
//     for (auto &var : col)
//       if (var == 'v')
//         new_col += 'v';

//     var_cols[i++] = new_col;
//   }

//   int cols_count = words[0].size (), var_index = 0;
//   vector<string> derived_words (words);
//   for (int i = cols_count - 1; i >= 0; i--) {
//     auto &current_col = var_cols[i];
//     auto next_col = i != 0 ? var_cols[i - 1] : "";
//     int new_var_index = var_index + current_col.size ();
//     set<char> next_col_set, current_col_set;
//     for (int j = 0; j < int (next_col.size ()); j++)
//       next_col_set.insert (var_values[j + new_var_index]);
//     for (int j = 0; j < int (current_col.size ()); j++)
//       current_col_set.insert (var_values[j + var_index]);

//     for (int j = 0; j < int (words.size ()); j++) {
//       char gc = words[j][i];

//       if (gc == 'x' && next_col_set.size () == 1) {
//         char value = *next_col_set.begin ();
//         if (value == 'v')
//           continue;
//         derived_words[j][i] = value == '1' ? 'u' : 'n';
//       } else if (is_in (gc, {'3', '5', 'A', 'B', 'C', 'D'}) &&
//                  current_col_set.size () == 1) {
//         char value = *current_col_set.begin ();
//         if (value == 'v')
//           continue;
//         switch (gc) {
//         case '3':
//           derived_words[j][i] = value == '0' ? '0' : 'u';
//           break;
//         case '5':
//           derived_words[j][i] = value == '0' ? 'n' : '0';
//           break;
//         case 'A':
//           derived_words[j][i] = value == '0' ? '1' : 'u';
//           break;
//         case 'B':
//           derived_words[j][i] = value == '0' ? '-' : 'u';
//           break;
//         case 'C':
//           derived_words[j][i] = value == '0' ? 'n' : '1';
//           break;
//         case 'D':
//           derived_words[j][i] = value == '0' ? 'n' : '-';
//           break;
//         }
//       } else if (is_in (gc, {'7', 'E', '?'})) {
//         // if (current_col_set.size () == 1 && next_col_set.size () == 1)
//         {
//         //   char value1 = *next_col_set.begin ();
//         //   char value2 = *current_col_set.begin ();
//         //   if (value1 == 'v' && value2 == 'v')
//         //     continue;

//         //   if (value1 == '0' && value2 == '0') {
//         //     derived_words[j][i] = 'n';
//         //   } else if (value1 == '0' && value2 == '1') {
//         //     derived_words[j][i] = gc == '?' ? '-' : gc == '7' ? '0' :
//         //     '1';
//         //   } else if (value1 == '1' && value2 == '0') {
//         //     derived_words[j][i] = 'u';
//         //   }
//         // }
//         if (current_col_set.size () == 1) {
//           char value = *current_col_set.begin ();
//           if (value == 'v')
//             continue;
//           derived_words[j][i] = value == '1' ? (gc == '?'   ? '-'
//                                                 : gc == '7' ? '0'
//                                                             : '1')
//                                              : 'x';
//         }
//         if (next_col_set.size () == 1) {
//           char value = *current_col_set.begin ();
//           if (value == 'v')
//             continue;
//           if (derived_words[j][i] == 'x')
//             derived_words[j][i] = value == '0' ? 'n' : '1';
//           else if (is_in (derived_words[j][i], {'?', '7', '5'}))
//             derived_words[j][i] = value == '1' ? 'u'
//                                                : (gc == '?'   ? 'D'
//                                                   : gc == '7' ? '5'
//                                                               : 'C');
//         }
//       }
//     }

//     var_index = new_var_index;
//   }

//   return derived_words;
// }

// vector<string> wordwise_propagate (vector<string> words, int64_t
// constant) {
//   auto count_vars = [] (vector<string> cols) {
//     int vars_count = 0;
//     for (auto &col : cols) {
//       for (auto &c : col) {
//         if (c != 'v')
//           continue;
//         vars_count++;
//       }
//     }

//     return vars_count;
//   };

//   int n = words[0].size (), m = words.size ();

//   // Skip if all words are grounded
//   bool all_grounded = true;
//   for (int i = 0; i < m; i++)
//     for (int j = 0; j < n; j++)
//       if (!is_in (words[i][j], {'n', 'u', '1', '0', '-'}))
//         all_grounded = false;
//   if (all_grounded)
//     return words;

//   // Generate variables
//   auto var_cols = gen_vars (words);
//   int vars_count = count_vars (var_cols);

//   // Adjust constant
//   for (int i = 0; i < m; i++)
//     constant = adjust_constant (words[i], constant);

//   // Linear scan
//   struct Island {
//     vector<string> cols;
//     vector<uint8_t> bits;
//   } stash;
//   vector<Island> islands;
//   vector<int> overflow_brute_force_indices;
//   for (int i = n - 1; i >= 0; i--) {
//     // Skip if there's nothing in the stash and there's no variable
//     either if (stash.cols.size () == 0 && var_cols[i].size () == 0)
//       continue;

//     uint8_t bit = constant >> (n - i - 1) & 1;
//     stash.bits.push_back (bit);
//     stash.cols.push_back (var_cols[i]);

//     // Check if it can overflow
//     // TODO: Improve the efficiency by simply tracking the carries
//     bool can_overflow = _can_overflow (stash.cols, stash.bits);

//     // If it cannot overflow, it should be cut off
//     bool island_ends = can_overflow ? false : true;

//     // Flush the stash
//     if (i == 0) {
//       island_ends = true;
//       if (can_overflow)
//         overflow_brute_force_indices.push_back (islands.size ());
//     }

//     if (island_ends) {
//       auto island = Island (stash);
//       islands.push_back (island);
//       stash.bits = {};
//       stash.cols = {};
//     }
//   }

//   printf ("Islands count: %ld\n", islands.size ());

//   // Derive the variable values
//   vector<char> var_values;
//   int island_index = -1;
//   for (Island &island : islands) {
//     island_index++;

//     string propagation;
//     if (count_vars (island.cols) <= WP_VARS_LIMIT) {
//       int64_t sum = 0;
//       int n = island.bits.size ();
//       for (int i = 0; i < n; i++)
//         sum += island.bits[i] * int64_t (pow (2, i));

//       if (is_in (island_index, overflow_brute_force_indices)) {
//         // int64_t min_gt = int64_t (pow (2, n)) - 1;
//         propagation = brute_force (island.cols, sum, -1, true);
//       } else {
//         propagation = brute_force (island.cols, sum);
//       }
//     } else {
//       // Skip if there are too many variables
//       for (auto &col : island.cols)
//         for (auto &var : col)
//           propagation.push_back ('v');
//     }

//     int local_index = 0;
//     for (int i = 0; i < int (island.cols.size ()); i++) {
//       auto &col = island.cols[i];
//       for (auto &var : col) {
//         if (var != 'v')
//           continue;
//         auto value = propagation[local_index++];
//         var_values.push_back (value);
//       }
//     }
//   }

//   // printf ("Cols:\n");
//   // for (auto &col : var_cols) {
//   //   printf ("%s\n", col.c_str ());
//   // }
//   // printf ("Values: ");
//   // for (auto &value : var_values) {
//   //   printf ("%c ", value);
//   // }
//   // printf ("\n");

//   // Fill in missing values
//   for (int i = int (var_values.size ()); i < vars_count; i++)
//     var_values.push_back ('v');
//   assert (int (var_values.size ()) == vars_count);

//   vector<string> derived_words =
//       apply_grounding (words, var_cols, var_values);

//   if (islands.size () == 0) {
//     for (int i = 0; i < words.size (); i++)
//       assert (words[i] == derived_words[i]);
//   }

//   return derived_words;
// }
} // namespace SHA256