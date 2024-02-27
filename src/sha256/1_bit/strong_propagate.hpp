#ifndef _sha256_1_bit_strong_propagate_hpp_INCLUDED
#define _sha256_1_bit_strong_propagate_hpp_INCLUDED

#include "../lru_cache.hpp"
#include "../state.hpp"
#include "../strong_propagate.hpp"
#include "../util.hpp"
#include <sstream>
#include <string>

using namespace std;

namespace SHA256 {
// TODO: Fix warnings regarding defining variables in the header
string add_masks[4] = {".+.++", "+..+", "+++", "+...++"};
int add_input_sizes[4] = {4, 3, 2, 5};

// Strong propagate (through branching) words by taking information inside
// the addition equation
cache::lru_cache<string, pair<string, string>>
    strong_propagate_cache (100e3);
inline void strong_propagate_branch_1bit (State &state,
                                          list<int> &decision_lits,
                                          Stats &stats) {
  state.soft_refresh ();
  auto _word_chars = [] (Word &word) {
    string chars;
    for (int i = 0; i < 32; i++)
      chars += word.chars[i];
    return chars;
  };
  auto _soft_word_chars = [] (SoftWord &word) {
    string chars;
    for (int i = 0; i < 32; i++)
      chars += *word.chars[i];
    return chars;
  };

  for (int op_id = op_add_w; op_id < op_add_t; op_id++)
    for (int step_i = 0; step_i < state.order; step_i++) {
      auto &marked_op =
          state.marked_operations_strong_prop[(OperationId) op_id][step_i];
      if (!marked_op)
        continue;
      marked_op = false;
      assert (op_id >= op_add_w);

      // Gather the input and output words
      auto &input_words = state.operations[step_i].inputs_by_op_id[op_id];
      auto &output_word =
          state.operations[step_i].outputs_by_op_id[op_id][2];
      int input_size = add_input_sizes[op_id - op_add_w];
      string mask = add_masks[op_id - op_add_w];
      assert (int (mask.size ()) - 1 == input_size);
      // TODO: Try applying the mask

      // Get the word characteristics
      vector<string> words_chars;
      for (int i = 0; i < input_size; i++)
        words_chars.push_back (_soft_word_chars (*input_words));
      words_chars.push_back (_word_chars (*output_word));

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

      // Do strong propagation
      vector<string> propagated_words;
      vector<int> underived_indices;
      if (!strong_propagate_cache.exists (cache_key)) {
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
            strong_propagate (underived_words, word_diffs_sum);

        // Cache the strong propagation
        pair<string, string> cache_value;
        for (auto &propagated_word : propagated_words)
          cache_value.first += propagated_word;
        for (auto &index : underived_indices)
          cache_value.second += to_string (index);
        strong_propagate_cache.put (cache_key, cache_value);
      } else {
        pair<string, string> cache_value =
            strong_propagate_cache.get (cache_key);
        int words_count = cache_value.first.size () / 32;
        for (int i = 0; i < words_count; i++) {
          string word = cache_value.first.substr (i * 32, 32);
          propagated_words.push_back (word);
        }

        for (auto &c : cache_value.second)
          underived_indices.push_back (c - '0');
      }
      assert (propagated_words.size () == underived_indices.size ());

      // printf ("Step %2d (Before), %d: ", step_i, op_id);
      // for (auto &chars : words_chars)
      //   cout << chars << " ";
      // cout << endl;

      // Deal with the propagated words
      for (int i = 0; i < int (underived_indices.size ()); i++) {
        auto index = underived_indices[i];
        string &original_chars = words_chars[index];
        string &propagated_chars = propagated_words[i];

        for (int j = 0; j < 32; j++)
          if (original_chars[j] != propagated_chars[j]) {
            assert (compare_gcs (original_chars[j], propagated_chars[j]));
            // printf ("Strong prop. %d: %c %c\n", op_id, original_chars[j],
            //         propagated_chars[j]);
            uint32_t ids[3];
            if (index == input_size) {
              // Output word
              ids[0] = output_word->ids_f[j];
              ids[1] = output_word->ids_g[j];
              ids[2] = output_word->char_ids[j];
            } else {
              // Input word
              ids[0] = input_words[index].ids_f[j];
              ids[1] = input_words[index].ids_g[j];
              ids[2] = input_words[index].char_ids[j];
            }

            // Branch on this differential character
            auto values = gc_values_1bit (propagated_chars[j]);
            for (int k = 2; k >= 0; k--) {
              if (values[k] == 0)
                continue;
              if (state.partial_assignment.get (ids[k]) != LIT_UNDEF)
                continue;
              int lit = values[k] * ids[k];
              decision_lits.push_back (lit);
              assert (state.partial_assignment.get (abs (lit)) ==
                      LIT_UNDEF);
              return;
            }
          }
      }

      // printf ("Step %2d (After), %d:  ", step_i, op_id);
      // for (auto &chars : words_chars)
      //   cout << chars << " ";
      // cout << endl;
    }
}
} // namespace SHA256

#endif