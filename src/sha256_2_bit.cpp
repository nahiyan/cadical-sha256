#include "sha256_2_bit.hpp"

#include <fstream>

namespace SHA256 {
unordered_map<string, string> two_bit_rules;

void load_two_bit_rules (const char *path) {
  std::ifstream db (path);
  if (!db) {
    printf ("Rules database not found. Can you ensure that '%s' "
            "exists in the current working directory?\n",
            path);
    exit (1);
  }
  int count = 0;
  std::string key, value;
  int id;
  while (db >> id >> key >> value) {
    key = to_string (id) + key;

    two_bit_rules.insert ({key, value});
    count++;
  }

  printf ("Loaded %d rules into %ld buckets\n", count,
          two_bit_rules.bucket_count ());
}

vector<Equation> derive_two_bit_equations (State &state,
                                           Operations *all_operations,
                                           int order) {
  vector<Equation> equations;

  auto derive_from_matrix = [] (vector<Equation> &equations, string matrix,
                                vector<Word> words, int col_index,
                                vector<string> names) {
    int matrix_i = -1;
    words.push_back (Word{}); // Pretend this to be the output word
    int words_count = words.size ();
    int blocks_count = 1;
    for (int k = 0; k < blocks_count; k++) {
      for (int i = 0; i < words_count; i++) {
        for (int j = i + 1; j < words_count; j++) {
          matrix_i++;
          if (matrix[matrix_i] == '2' || words_count - 1 == i ||
              words_count - 1 == j)
            continue;

          uint8_t diff = matrix[matrix_i] == '1' ? 0 : 1;
          uint32_t selected_ids[] = {k == 0 ? words[i].ids_f[col_index]
                                            : words[i].ids_g[col_index],
                                     k == 0 ? words[j].ids_f[col_index]
                                            : words[j].ids_g[col_index]};
          Equation equation;
          equation.ids[0] = selected_ids[0];
          equation.ids[1] = selected_ids[1];
          equation.names[0] = names[i];
          equation.names[1] = names[j];
          equation.diff = diff;
          // printf ("Equation: %s %s %s\n", equation.names[0].c_str (),
          //         diff == 0 ? "=" : "=/=", equation.names[1].c_str ());

          equations.push_back (equation);
        }
      }
    }
  };

  for (int i = 0; i < order; i++) {
    auto &step_operations = all_operations[i];
    auto &step_state = state.steps[i];

    if (i >= 16) {
      {
        // s0
        auto &inputs_ = step_operations.s0.inputs;
        auto &output = step_state.s0.chars;
        for (int j = 0; j < 32; j++) {
          vector<Word> inputs = {inputs_[0], inputs_[1]};
          if (j >= 3)
            inputs.push_back (inputs_[2]);

          string key;
          key += to_string (j >= 3 ? TWO_BIT_XOR3_ID : TWO_BIT_XOR2_ID);
          for (auto &input : inputs)
            key += input.chars[j];
          key += output[j];
          string value = two_bit_rules[key];

          // TODO: Naming the variables shouldn't be done outside
          int indices[] = {(31 - j + 7) % 32, (31 - j + 18) % 32,
                           31 - j + 3};
          if (!value.empty ())
            derive_from_matrix (
                equations, value, inputs, j,
                {"W_" + to_string (i - 15) + "," + to_string (indices[0]),
                 "W_" + to_string (i - 15) + "," + to_string (indices[1]),
                 "W_" + to_string (i - 15) + "," + to_string (indices[2])});
        }
      }
      {
        // s1
        auto &inputs_ = step_operations.s1.inputs;
        auto &output = step_state.s1.chars;
        for (int j = 0; j < 32; j++) {
          vector<Word> inputs = {inputs_[0], inputs_[1]};
          if (j >= 10)
            inputs.push_back (inputs_[2]);

          string key;
          key += to_string (j >= 10 ? TWO_BIT_XOR3_ID : TWO_BIT_XOR2_ID);
          for (auto &input : inputs)
            key += input.chars[j];
          key += output[j];
          string value = two_bit_rules[key];

          int indices[] = {(31 - j + 17) % 32, (31 - j + 19) % 32,
                           31 - j + 10};
          if (!value.empty ())
            derive_from_matrix (
                equations, value, inputs, j,
                {"W_" + to_string (i - 2) + "," + to_string (indices[0]),
                 "W_" + to_string (i - 2) + "," + to_string (indices[1]),
                 "W_" + to_string (i - 2) + "," + to_string (indices[2])});
        }
      }
    }

    {
      // sigma0
      auto &inputs_ = step_operations.sigma0.inputs;
      auto &output = step_state.sigma0.chars;
      for (int j = 0; j < 32; j++) {
        vector<Word> inputs = {inputs_[0], inputs_[1], inputs_[2]};
        string key;
        key += to_string (TWO_BIT_XOR3_ID);
        for (auto &input : inputs)
          key += input.chars[j];
        key += output[j];
        string value = two_bit_rules[key];

        int indices[] = {(31 - j + 2) % 32, (31 - j + 13) % 32,
                         (31 - j + 22) % 32};
        if (!value.empty ())
          derive_from_matrix (
              equations, value, inputs, j,
              {"A_" + to_string (i - 1) + "," + to_string (indices[0]),
               "A_" + to_string (i - 1) + "," + to_string (indices[1]),
               "A_" + to_string (i - 1) + "," + to_string (indices[2])});
      }
    }
    {
      // sigma1
      auto &inputs_ = step_operations.sigma1.inputs;
      auto &output = step_state.sigma1.chars;
      for (int j = 0; j < 32; j++) {
        vector<Word> inputs = {inputs_[0], inputs_[1], inputs_[2]};
        string key;
        key += to_string (TWO_BIT_XOR3_ID);
        for (auto &input : inputs)
          key += input.chars[j];
        key += output[j];
        string value = two_bit_rules[key];

        int indices[] = {(31 - j + 6) % 32, (31 - j + 11) % 32,
                         (31 - j + 25) % 32};
        if (!value.empty ())
          derive_from_matrix (
              equations, value, inputs, j,
              {"E_" + to_string (i - 1) + "," + to_string (indices[0]),
               "E_" + to_string (i - 1) + "," + to_string (indices[1]),
               "E_" + to_string (i - 1) + "," + to_string (indices[2])});
      }
    }
    {
      // maj
      auto &inputs_ = step_operations.maj.inputs;
      auto &output = step_state.maj.chars;
      for (int j = 0; j < 32; j++) {
        vector<Word> inputs = {inputs_[0], inputs_[1], inputs_[2]};
        string key;
        key += to_string (TWO_BIT_MAJ_ID);
        for (auto &input : inputs)
          key += input.chars[j];
        key += output[j];
        string value = two_bit_rules[key];
        if (!value.empty ())
          derive_from_matrix (
              equations, value, inputs, j,
              {"A_" + to_string (i - 1) + "," + to_string (31 - j),
               "A_" + to_string (i - 2) + "," + to_string (31 - j),
               "A_" + to_string (i - 3) + "," + to_string (31 - j)});
      }
    }
    {
      // ch
      auto &inputs_ = step_operations.ch.inputs;
      auto &output = step_state.ch.chars;
      for (int j = 0; j < 32; j++) {
        vector<Word> inputs = {inputs_[0], inputs_[1], inputs_[2]};
        string key;
        key += to_string (TWO_BIT_IF_ID);
        for (auto &input : inputs)
          key += input.chars[j];
        key += output[j];
        string value = two_bit_rules[key];
        if (!value.empty ())
          derive_from_matrix (
              equations, value, inputs, j,
              {"E_" + to_string (i - 1) + "," + to_string (31 - j),
               "E_" + to_string (i - 2) + "," + to_string (31 - j),
               "E_" + to_string (i - 3) + "," + to_string (31 - j)});
      }
    }
  }

  return equations;
}
} // namespace SHA256