#ifndef _sha256_1_bit_wordwise_propagate_hpp_INCLUDED
#define _sha256_1_bit_wordwise_propagate_hpp_INCLUDED

#include "../lru_cache.hpp"
#include "../state.hpp"
#include "../util.hpp"
#include "../wordwise_propagate.hpp"
#include <sstream>
#include <string>

using namespace std;

namespace SHA256 {
#if IS_1BIT
// TODO: Fix warnings regarding defining variables in the header
string add_masks[4] = {".+.++", "+..+", "+++", "+...++"};
int add_input_sizes[4] = {4, 3, 2, 5};

// Wordwise propagate (through branching) words by taking information inside
// the addition equation
cache::lru_cache<string, pair<string, string>>
    wordwise_propagate_cache (100e3);
inline void wordwise_propagate_branch_1bit (State &state,
                                            list<int> &decision_lits,
                                            Stats &stats) {
  state.soft_refresh ();
  auto _word_chars = [] (Word &word) {
    string chars;
    for (int i = 31; i >= 0; i--)
      chars += word.chars[i];
    return chars;
  };
  auto _soft_word_chars = [] (SoftWord &word, bool assume_dash = false) {
    string chars;
    for (int i = 31; i >= 0; i--)
      if (assume_dash)
        chars += *word.chars[i] == '?' ? '-' : *word.chars[i];
      else
        chars += *word.chars[i];
    return chars;
  };

  for (int op_id = op_add_w; op_id <= op_add_t; op_id++)
    for (int step_i = 0; step_i < state.order; step_i++) {
      auto &marked_op =
          state
              .marked_operations_wordwise_prop[(OperationId) op_id][step_i];
      if (!marked_op)
        continue;
      marked_op = false;
      assert (op_id >= op_add_w && op_id <= op_add_t);

      // Gather the input and output words
      auto &input_words = state.operations[step_i].inputs_by_op_id[op_id];
      auto &output_word =
          state.operations[step_i].outputs_by_op_id[op_id][2];
      int input_size = add_input_sizes[op_id - op_add_w];
      string mask = add_masks[op_id - op_add_w];
      assert (int (mask.size ()) - 1 == input_size);

      // Get the word characteristics
      vector<string> words_chars;
      for (int i = 0; i < input_size; i++)
        words_chars.push_back (_soft_word_chars (input_words[i], true));
      words_chars.push_back (_word_chars (output_word[0]));

      // Generate the cache key
      string cache_key;
      {
        stringstream ss;
        ss << op_id << " ";
        for (auto &word_chars_ : words_chars)
          ss << word_chars_;
        cache_key = ss.str ();
        assert (!cache_key.empty ());
      }

      // Do wordwise propagation
      vector<string> propagated_words;
      vector<int> underived_indices;
      if (!wordwise_propagate_cache.exists (cache_key)) {
        // Calculate the word diffs
        bool input_const_unknown = false, output_const_unknown = false;
        vector<string> underived_words;
        vector<int64_t> word_diffs;
        int i = -1;
        for (auto &word_chars_ : words_chars) {
          i++;
          int64_t word_diff = _word_diff (word_chars_);
          bool is_output = i == input_size;
          if (word_diff == -1) {
            underived_indices.push_back (i);
            underived_words.push_back (word_chars_);

            if (is_output)
              output_const_unknown = true;
            else
              input_const_unknown = true;
          } else {
            word_diffs.push_back (is_output ? word_diff : -word_diff);
          }
        }

        // Skip if it involves subtraction
        if (input_const_unknown && output_const_unknown)
          continue;

        // Skip if underived words is 0 or more than 2
        int underived_count = underived_indices.size ();
        if (underived_count == 0 || underived_count > 2)
          continue;

        // Calculate the sum of the the word diffs
        int64_t word_diffs_sum = 0;
        for (auto &word_diff : word_diffs)
          word_diffs_sum += word_diff;
        word_diffs_sum = e_mod (word_diffs_sum, int64_t (pow (2, 32)));

        // Derive the underived words
        propagated_words = wordwise_propagate (
            underived_words,
            output_const_unknown ? -word_diffs_sum : word_diffs_sum);

        // printf ("Step %2d (Before), %d: ", step_i, op_id);
        // for (auto &chars : words_chars)
        //   cout << chars << " ";
        // cout << endl;
        // printf ("Step %2d (After), %d:  ", step_i, op_id);
        // for (auto &chars : propagated_words)
        //   cout << chars << " ";
        // cout << endl;
        // printf ("Constant = %ld (%ld underived count)\n", word_diffs_sum,
        //         underived_words.size ());

        // Cache the wordwise propagation result
        pair<string, string> cache_value;
        for (auto &propagated_word : propagated_words)
          cache_value.first += propagated_word;
        for (auto &index : underived_indices)
          cache_value.second += to_string (index);
        wordwise_propagate_cache.put (cache_key, cache_value);
      } else {
        pair<string, string> cache_value =
            wordwise_propagate_cache.get (cache_key);
        int words_count = cache_value.first.size () / 32;
        for (int i = 0; i < words_count; i++) {
          string word = cache_value.first.substr (i * 32, 32);
          propagated_words.push_back (word);
        }

        assert ('5' - '0' == 5);
        for (auto &c : cache_value.second)
          underived_indices.push_back (c - '0');
      }
      assert (propagated_words.size () == underived_indices.size ());

      // Deal with the propagated words
      for (int i = 0; i < int (underived_indices.size ()); i++) {
        auto index = underived_indices[i];

        if (mask[index] == '.')
          continue;

        string &original_chars = words_chars[index];
        string &propagated_chars = propagated_words[i];

        // Try dealing with the MSBs first
        for (int j = 31; j >= 0; j--)
          if (original_chars[j] != propagated_chars[j]) {
            assert (compare_gcs (original_chars[j], propagated_chars[j]));
            // printf ("Wordwise prop. %d: %c %c\n", op_id,
            // original_chars[j],
            //         propagated_chars[j]);
            uint32_t ids[3];
            if (index == input_size) {
              // Output word
              ids[0] = output_word->ids_f[31 - j];
              ids[1] = output_word->ids_g[31 - j];
              ids[2] = output_word->char_ids[31 - j];
            } else {
              // Input word
              ids[0] = input_words[index].ids_f[31 - j];
              ids[1] = input_words[index].ids_g[31 - j];
              ids[2] = input_words[index].char_ids[31 - j];
            }

            // Branch on this differential character
            auto values = gc_values_1bit (propagated_chars[j]);
            assert (values.size () == 3);
            for (int k = 2; k >= 0; k--) {
              if (values[k] == 0)
                continue;
              if (state.partial_assignment.get (ids[k]) != LIT_UNDEF)
                continue;
              int lit = values[k] * ids[k];
              assert (lit != 0);
              decision_lits.push_back (lit);
              assert (state.partial_assignment.get (abs (lit)) ==
                      LIT_UNDEF);
              // printf ("Wordwise propagated (count %ld)\n",
              //         underived_indices.size ());

              // bool unknown_input = false, unknown_output = false;
              // printf ("Indices: ");
              // for (auto &index : underived_indices) {
              //   printf ("%d ", index);
              //   if (index == input_size)
              //     unknown_output = true;
              //   else
              //     unknown_input = true;
              // }
              // printf ("\n");

              // for (auto &word : words_chars) {
              //   printf ("%s: %ld\n", word.c_str (), _word_diff (word));
              // }

#if PRINT_WP_REASON_CLAUSE
              // Construct the reason clause
              Reason reason;
              // printf ("Debug (%c, %c, %d, %d, %d %d, %d): ",
              //         original_chars[j], propagated_chars[j], lit,
              //         input_size, unknown_input, unknown_output, k);
              int propagated_lit = lit;
              for (int a = 0; a < input_size; a++) {
                auto &word = input_words[a];
                for (int b = 0; b < 32; b++) {
                  uint32_t ids[] = {word.ids_f[b], word.ids_g[b],
                                    word.char_ids[b]};
                  auto values = gc_values_1bit (*word.chars[b]);
                  // printf ("%c", *word.chars[31 - b]);
                  assert (values.size () == 3);
                  for (int c = 0; c < 3; c++) {
                    int lit = values[c] * ids[c];
                    if (lit == 0)
                      continue;
                    assert (state.partial_assignment.get (ids[c]) ==
                            (lit > 0 ? LIT_TRUE : LIT_FALSE));
                    reason.antecedent.push_back (-lit);
                  }
                }
                // printf (" ");
              }
              {
                auto &word = output_word[i];
                for (int b = 0; b < 32; b++) {
                  uint32_t ids[] = {word.ids_f[b], word.ids_g[b],
                                    word.char_ids[b]};
                  auto values = gc_values_1bit (word.chars[b]);
                  // printf ("%c", word.chars[31 - b]);
                  assert (values.size () == 3);
                  for (int c = 0; c < 3; c++) {
                    auto &id = ids[c];
                    int lit = values[c] * id;
                    if (lit == 0)
                      continue;
                    assert (state.partial_assignment.get (ids[c]) ==
                            (lit > 0 ? LIT_TRUE : LIT_FALSE));
                    reason.antecedent.push_back (-lit);
                  }
                }
                // printf ("\n");
              }
              vector<int> reason_clause = vector (reason.antecedent);
              reason_clause.push_back (propagated_lit);

              // printf ("Debug: op_id = %s; step = %d\n",
              //         op_id == op_add_w   ? "add.W"
              //         : op_id == op_add_e ? "add.E"
              //         : op_id == op_add_t ? "add.T"
              //                             : "invalid",
              //         step_i);
              // printf ("Debug clause (%ld): ", reason_clause.size ());
              // for (auto &lit : reason_clause) {
              //   printf ("%d ", lit);
              // }
              // printf ("\n");

              printf ("Reason clause: ");
              for (auto &lit : reason_clause) {
                if (!state.vars_info[abs (lit)].is_fixed)
                  printf ("%d ", lit);
              }
              printf ("\n");
#endif

              return;
            }
          }
      }
    }
}
#endif
} // namespace SHA256

#endif