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
} // namespace SHA256