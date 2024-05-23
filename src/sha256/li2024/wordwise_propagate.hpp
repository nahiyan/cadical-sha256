#ifndef _sha256_li2024_wordwise_propagate_hpp_INCLUDED
#define _sha256_li2024_wordwise_propagate_hpp_INCLUDED

#include "../lru_cache.hpp"
#include "../state.hpp"
#include "../util.hpp"
#include "../wordwise_propagate.hpp"
#include <sstream>
#include <string>

using namespace std;

namespace SHA256 {
#if IS_LI2024
// TODO: Fix warnings regarding defining variables in the header
// string add_masks[4] = {".+.++", "+..+", "+++", "+...++"};

// Wordwise propagate (through branching) words by taking information inside
// the addition equation
cache::lru_cache<string, pair<string, string>>
    wordwise_propagate_cache (100e3);
inline void wordwise_propagate_branch_li2024 (State &state,
                                              list<int> &decision_lits,
                                              Stats &stats) {
  state.soft_refresh ();
  auto _word_chars = [] (Word &word) {
    string chars;
    for (int i = 31; i >= 0; i--)
      chars += word.chars[i];
    return chars;
  };
  auto _soft_word_chars = [] (SoftWord &word) {
    string chars;
    for (int i = 31; i >= 0; i--) {
      assert (word.char_ids[0][i] != 0);
      assert (word.char_ids[1][i] != 0);
      chars += *word.chars[i];
      assert (*word.chars[i] == 'u' || *word.chars[i] == 'n' ||
              *word.chars[i] == '-' || *word.chars[i] == '?');
    }
    assert (chars.size () == 32);
    return chars;
  };

  for (int op_id = op_add_b2; op_id < op_add_b4; op_id++)
    for (int step_i = 0; step_i < state.order; step_i++) {
      auto &marked_op =
          state
              .marked_operations_wordwise_prop[(OperationId) op_id][step_i];
      if (!marked_op)
        continue;
      marked_op = false;
      assert (op_id >= op_add_b2);

      // Gather the input and output words
      auto &input_words = state.operations[step_i].inputs_by_op_id[op_id];
      auto &output_word =
          state.operations[step_i].outputs_by_op_id[op_id][1];
      int input_size = 2;

      // Get the word characteristics
      vector<string> words_chars;
      for (int i = 0; i < input_size; i++)
        words_chars.push_back (_soft_word_chars (*input_words));
      words_chars.push_back (_soft_word_chars (output_word));

      // Generate the cache key
      string cache_key;
      {
        stringstream ss;
        ss << op_id << " ";
        for (auto &word_chars : words_chars)
          ss << word_chars;
        cache_key = ss.str ();
        assert (!cache_key.empty ());
      }

      // Do wordwise propagation
      vector<string> propagated_words;
      vector<int> underived_indices;
      if (!wordwise_propagate_cache.exists (cache_key)) {
        // Calculate the word diffs
        vector<string> underived_words;
        vector<int64_t> word_diffs;
        int i = -1;
        for (auto &word_chars : words_chars) {
          i++;
          int64_t word_diff = _word_diff (word_chars);
          if (word_diff == -1) {
            underived_indices.push_back (i);
            underived_words.push_back (word_chars);
          } else {
            word_diffs.push_back (i == input_size ? word_diff : -word_diff);
          }
        }

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
        propagated_words =
            wordwise_propagate (underived_words, word_diffs_sum);

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
        string &original_chars = words_chars[index];
        string &propagated_chars = propagated_words[i];

        // Try dealing with the MSBs first
        for (int j = 31; j >= 0; j--)
          if (original_chars[j] != propagated_chars[j]) {
            assert (compare_gcs (original_chars[j], propagated_chars[j]));
            // printf ("Strong prop. %d: %c %c\n", op_id, original_chars[j],
            //         propagated_chars[j]);
            uint32_t ids[2];
            if (index == input_size) {
              // Output word
              ids[0] = output_word.char_ids[0][31 - j];
              ids[1] = output_word.char_ids[1][31 - j];
            } else {
              // Input word
              ids[0] = output_word.char_ids[0][31 - j];
              ids[1] = output_word.char_ids[1][31 - j];
            }

            // Branch on this differential character
            auto values = gc_values_li2024 (propagated_chars[j]);
            assert (values.size () == 2);
            for (int k = 1; k >= 0; k--) {
              if (state.partial_assignment.get (ids[k]) != LIT_UNDEF)
                continue;
              int lit = values[k] * ids[k];
              decision_lits.push_back (lit);
              assert (state.partial_assignment.get (abs (lit)) ==
                      LIT_UNDEF);
              // printf ("Wordwise propagated (count %ld)\n",
              //         underived_indices.size ());
              return;
            }
          }
      }
    }
}
#endif
} // namespace SHA256

#endif