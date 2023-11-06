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

void derive_two_bit_equations (State &state, Operations *all_operations,
                               int order) {
  for (int i = 0; i < order; i++) {
    auto &step_operations = all_operations[i];
    auto &step_state = state.steps[i];

    if (i >= 16) {
      {
        // s0
        auto &inputs = step_operations.s0.inputs;
        auto &output = step_state.s0.chars;
        for (int j = 0; j < 32; j++) {
          string key;
          key += to_string (j >= 3 ? TWO_BIT_XOR3_ID : TWO_BIT_XOR2_ID);
          key += inputs[0].chars[j];
          key += inputs[1].chars[j];
          if (j >= 3)
            key += inputs[2].chars[j];
          key += output[j];
          string value = two_bit_rules[key];
          // printf ("%d %d %s: %s\n", i, j, key.c_str (), value.c_str ());
        }
      }
      {
        // s1
        auto &inputs = step_operations.s1.inputs;
        auto &output = step_state.s1.chars;
        for (int j = 0; j < 32; j++) {
          string key;
          key += to_string (j >= 10 ? TWO_BIT_XOR3_ID : TWO_BIT_XOR2_ID);
          key += inputs[0].chars[j];
          key += inputs[1].chars[j];
          if (j >= 10)
            key += inputs[2].chars[j];
          key += output[j];
          string value = two_bit_rules[key];
          // printf ("%d %d %s: %s\n", i, j, key.c_str (), value.c_str ());
        }
      }
    }

    {
      // sigma0
      auto &inputs = step_operations.sigma0.inputs;
      auto &output = step_state.sigma0.chars;
      for (int j = 0; j < 32; j++) {
        string key;
        key += to_string (TWO_BIT_XOR3_ID);
        key += inputs[0].chars[j];
        key += inputs[1].chars[j];
        key += inputs[2].chars[j];
        key += output[j];
        string value = two_bit_rules[key];
        // printf ("%d %d %s: %s\n", i, j, key.c_str (), value.c_str ());
      }
    }
    {
      // sigma1
      auto &inputs = step_operations.sigma1.inputs;
      auto &output = step_state.sigma1.chars;
      for (int j = 0; j < 32; j++) {
        string key;
        key += to_string (TWO_BIT_XOR3_ID);
        key += inputs[0].chars[j];
        key += inputs[1].chars[j];
        key += inputs[2].chars[j];
        key += output[j];
        string value = two_bit_rules[key];
        // printf ("%d %d %s: %s\n", i, j, key.c_str (), value.c_str ());
      }
    }
    {
      // maj
      auto &inputs = step_operations.maj.inputs;
      auto &output = step_state.maj.chars;
      for (int j = 0; j < 32; j++) {
        string key;
        key += to_string (TWO_BIT_MAJ_ID);
        key += inputs[0].chars[j];
        key += inputs[1].chars[j];
        key += inputs[2].chars[j];
        key += output[j];
        string value = two_bit_rules[key];
        // printf ("%d %d %s: %s\n", i, j, key.c_str (), value.c_str ());
      }
    }
    {
      // ch
      auto &inputs = step_operations.ch.inputs;
      auto &output = step_state.ch.chars;
      for (int j = 0; j < 32; j++) {
        string key;
        key += to_string (TWO_BIT_IF_ID);
        key += inputs[0].chars[j];
        key += inputs[1].chars[j];
        key += inputs[2].chars[j];
        key += output[j];
        string value = two_bit_rules[key];
        // printf ("%d %d %s: %s\n", i, j, key.c_str (), value.c_str ());
      }
    }
  }
}
} // namespace SHA256