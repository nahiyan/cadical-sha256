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
int add_input_sizes[3] = {4, 4, 5};
// K in little-endian as per our convention
string k[64] = {
    "00011001111101000101000101000010", "10001001001000101110110010001110",
    "11110011110111110000001110101101", "10100101110110111010110110010111",
    "11011010010000110110101010011100", "10001111100010001000111110011010",
    "00100101010000011111110001001001", "10101011011110100011100011010101",
    "00011001010101011110000000011011", "10000000110110101100000101001000",
    "01111101101000011000110000100100", "11000011101111100011000010101010",
    "00101110101110100111110101001110", "01111111100011010111101100000001",
    "11100101011000000011101111011001", "00101110100011111101100110000011",
    "10000011100101101101100100100111", "01100001111000100111110111110111",
    "01100011101110011000001111110000", "00110011100001010011000000100100",
    "11110110001101001001011110110100", "01010101001000010010111001010010",
    "00111011100101010000110100111010", "01011011000100011001111101101110",
    "01001010100010100111110000011001", "10110110011000111000110000010101",
    "00010011111001001100000000001101", "11100011111111101001101011111101",
    "11001111110100000000011101100011", "11100010100010011110010110101011",
    "10001010110001100101001101100000", "11100110100101001001010000101000",
    "10100001010100001110110111100100", "00011100100001001101100001110100",
    "00111111101101100011010010110010", "11001000101100000001110011001010",
    "00101010110011100101000010100110", "11011101010100000101011001101110",
    "01110100100100110100001110000001", "10100001001101000100111001001001",
    "10000101000101111111110101000101", "11010010011001100101100000010101",
    "00001110110100011101001001000011", "11000101100010100011011011100011",
    "10011000000101110100100110001011", "00100100011000001001100101101011",
    "10100001101011000111000000101111", "00001110000001010101011000001000",
    "01101000100000110010010110011000", "00010000001101101110110001111000",
    "00110010111011100001001011100100", "10101101001111010000110100101100",
    "11001101001100000011100010011100", "01010010010101010001101101110010",
    "11110010010100110011100111011010", "11001111111101100111010000010110",
    "01110111010000011111000100101110", "11110110110001101010010100011110",
    "00101000000111100001001100100001", "00010000010000001110001100110001",
    "01011111111111110111110100001001", "11010111001101100000101000100101",
    "11101111110001011001111101111101", "01001111000111101000111001100011",
};

// Wordwise propagate (through branching) words by taking information inside
// the addition equation
cache::lru_cache<string, pair<string, string>>
    wordwise_propagate_cache (100e3);
inline void wordwise_propagate_branch_li2024 (State &state,
                                              list<int> &decision_lits,
                                              Stats &stats) {
  state.soft_refresh ();
  // The following 2 functions will convert the conditions to big-endian for
  // the wordwise propagation engine
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
              *word.chars[i] == '-' || *word.chars[i] == '?' ||
              *word.chars[i] == 'x');
    }
    assert (chars.size () == 32);
    return chars;
  };

  for (int op_id = op_add_w; op_id <= op_add_e; op_id++)
    for (int step_i = 0; step_i < state.order; step_i++) {
      auto &marked_op =
          state
              .marked_operations_wordwise_prop[(OperationId) op_id][step_i];
      if (!marked_op)
        continue;
      marked_op = false;
      assert (op_id >= op_add_w && op_id <= op_add_e);

      // Gather the input and output words
      auto &input_words = state.operations[step_i].inputs_by_op_id[op_id];
      auto &output_word =
          state.operations[step_i].outputs_by_op_id[op_id][2];
      int input_size = add_input_sizes[op_id - op_add_w];

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
            // Everything on the LHS is positive
            word_diffs.push_back (i == input_size ||
                                          (op_id == op_add_a && i == 1)
                                      ? word_diff
                                      : -word_diff);
          }
        }
        if (op_id == op_add_e) {
          string chars = k[step_i];
          reverse (chars.begin (), chars.end ());
          word_diffs.push_back (_word_diff (chars));
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
        for (int j = 0; j < 32; j++)
          if (original_chars[j] != propagated_chars[j]) {
            assert (compare_gcs (original_chars[j], propagated_chars[j]));
            // printf ("Wordwise prop. %d: %c %c\n", op_id,
            // original_chars[j],
            //         propagated_chars[j]);
            uint32_t ids[2];
            if (index == input_size) {
              // Output word
              ids[0] = output_word->char_ids[0][31 - j];
              ids[1] = output_word->char_ids[1][31 - j];
            } else {
              // Input word
              ids[0] = input_words[index].char_ids[0][31 - j];
              ids[1] = input_words[index].char_ids[1][31 - j];
            }

            // Branch on this differential character
            auto values = gc_values_li2024 (propagated_chars[j]);
            assert (values.size () == 2);
            for (int k = 1; k >= 0; k--) {
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

              // Construct the reason clause
              Reason reason;
              int propagated_lit = lit;
              for (int a = 0; a < input_size; a++) {
                auto &word = input_words[a];
                for (int b = 0; b < 32; b++) {
                  auto values = gc_values_li2024 (*word.chars[b]);
                  assert (values.size () == 2);
                  for (int c = 0; c < 2; c++) {
                    auto &id = word.char_ids[c][b];
                    int lit = values[c] * id;
                    if (lit == 0)
                      continue;
                    assert (state.partial_assignment.get (id) ==
                            (lit > 0 ? LIT_TRUE : LIT_FALSE));
                    reason.antecedent.push_back (-lit);
                  }
                }
              }
              {
                auto &word = output_word[i];
                for (int b = 0; b < 32; b++) {
                  auto values = gc_values_li2024 (word.chars[b]);
                  assert (values.size () == 2);
                  for (int c = 0; c < 2; c++) {
                    auto &id = word.char_ids[c][b];
                    int lit = values[c] * id;
                    if (lit == 0)
                      continue;
                    assert (state.partial_assignment.get (id) ==
                            (lit > 0 ? LIT_TRUE : LIT_FALSE));
                    reason.antecedent.push_back (-lit);
                  }
                }
              }
              vector<int> reason_clause = vector (reason.antecedent);
              reason_clause.push_back (propagated_lit);
              printf ("Reason clause: ");
              for (auto &lit : reason_clause)
                printf ("%d ", lit);
              printf ("\n");

              return;
            }
          }
      }
    }
}
#endif
} // namespace SHA256

#endif