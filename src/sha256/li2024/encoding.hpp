#ifndef _sha256_li2024_encoding_hpp_INCLUDED
#define _sha256_li2024_encoding_hpp_INCLUDED

#include "../../cadical.hpp"
#include "../sha256.hpp"
#include <regex>

using namespace std;

namespace SHA256 {
inline void add_li2024_variables (string line, CaDiCaL::Solver *&solver) {
  auto &state = Propagator::state;

  istringstream iss (line);
  string key;
  int value;
  iss >> key >> value;

  // Determine the order
  if (key == "order") {
    state.order = value;
    state.end_step -= 4;

    // Initialize the characteristics
    for (int i = 0; i < state.order + 4; i++) {
      state.steps[i].a.chars = string (32, '?');
      state.steps[i].e.chars = string (32, '?');
      if (i < state.order) {
        state.steps[i].w.chars = string (32, '?');
        for (int j = 0; j < 10; j++)
          state.steps[i].b[j].chars = string (32, '?');
        for (int j = 0; j < 8; j++)
          state.steps[i].c[j].chars = string (33, '?');
      }
    }

    // Since this is the last comment, set the operations
    state.set_operations ();

    printf ("Initial state:\n");
    state.soft_refresh ();
    state.print ();
    return;
  }

  // Get the step
  regex pattern ("(.+_)(\\d+)_(\\d+)");
  smatch match;
  int step, col;
  string actual_prefix;
  if (regex_search (key, match, pattern)) {
    actual_prefix = match[1];
    step = stoi (match[2].str ());
    col = stoi (match[3].str ());
  } else {
    // printf ("Warning: Failed to load IDs from %s\n", key.c_str ());
    return;
  }

  // Offset the steps for A and E
  if (actual_prefix == "xv_" || actual_prefix == "xd_" ||
      actual_prefix == "yv_" || actual_prefix == "yd_")
    step = ABS_STEP (step);

  // Pair the prefixes with the words
  vector<pair<string, Word &>> prefix_pairs = {
      {"xv_", state.steps[step].a},     {"xd_", state.steps[step].a},
      {"yv_", state.steps[step].e},     {"yd_", state.steps[step].e},
      {"wv_", state.steps[step].w},     {"wd_", state.steps[step].w},
      {"bv0_", state.steps[step].b[0]}, {"bd0_", state.steps[step].b[0]},
      {"bv1_", state.steps[step].b[1]}, {"bd1_", state.steps[step].b[1]},
      {"bv2_", state.steps[step].b[2]}, {"bd2_", state.steps[step].b[2]},
      {"bv3_", state.steps[step].b[3]}, {"bd3_", state.steps[step].b[3]},
      {"bv4_", state.steps[step].b[4]}, {"bd4_", state.steps[step].b[4]},
      {"bv5_", state.steps[step].b[5]}, {"bd5_", state.steps[step].b[5]},
      {"bv6_", state.steps[step].b[6]}, {"bd6_", state.steps[step].b[6]},
      {"bv7_", state.steps[step].b[7]}, {"bd7_", state.steps[step].b[7]},
      {"bv8_", state.steps[step].b[8]}, {"bd8_", state.steps[step].b[8]},
      {"bv9_", state.steps[step].b[9]}, {"bd9_", state.steps[step].b[9]},
      {"cv0_", state.steps[step].c[0]}, {"cd0_", state.steps[step].c[0]},
      {"cv1_", state.steps[step].c[1]}, {"cd1_", state.steps[step].c[1]},
      {"cv2_", state.steps[step].c[2]}, {"cd2_", state.steps[step].c[2]},
      {"cv3_", state.steps[step].c[3]}, {"cd3_", state.steps[step].c[3]},
      {"cv4_", state.steps[step].c[4]}, {"cd4_", state.steps[step].c[4]},
      {"cv5_", state.steps[step].c[5]}, {"cd5_", state.steps[step].c[5]},
      {"cv6_", state.steps[step].c[6]}, {"cd6_", state.steps[step].c[6]},
      {"cv7_", state.steps[step].c[7]}, {"cd7_", state.steps[step].c[7]},
  };

  for (auto &pair : prefix_pairs) {
    auto &word = pair.second;
    string prefix = pair.first;
    if (prefix != actual_prefix)
      continue;

    VariableName var_name = Unknown;
    if (prefix == "xv_" || prefix == "xd_")
      var_name = A;
    else if (prefix == "yv_" || prefix == "yd_")
      var_name = E;
    else if (prefix == "wv_" || prefix == "wd_")
      var_name = W;
    else if (prefix == "bv0_")
      var_name = B0;
    else if (prefix == "bv1_")
      var_name = B1;
    else if (prefix == "bv2_")
      var_name = B2;
    else if (prefix == "bv3_")
      var_name = B3;
    else if (prefix == "bv4_")
      var_name = B4;
    else if (prefix == "bv5_")
      var_name = B5;
    else if (prefix == "bv6_")
      var_name = B6;
    else if (prefix == "bv7_")
      var_name = B7;
    else if (prefix == "bv8_")
      var_name = B8;
    else if (prefix == "bv9_")
      var_name = B9;
    else if (prefix == "cv0_")
      var_name = C0;
    else if (prefix == "cv1_")
      var_name = C1;
    else if (prefix == "cv2_")
      var_name = C2;
    else if (prefix == "cv3_")
      var_name = C3;
    else if (prefix == "cv4_")
      var_name = C4;
    else if (prefix == "cv5_")
      var_name = C5;
    else if (prefix == "cv6_")
      var_name = C6;
    else if (prefix == "cv7_")
      var_name = C7;

    if (var_name == A) {
      state.start_step = min (step, state.start_step);
      state.end_step = max (step, state.end_step);
    }

    int id = value;
    state.vars_info[id] = {&word, step, col, var_name};
    int char_id_type =
        (prefix == "xv_" || prefix == "yv_" || prefix == "wv_" ||
         prefix == "bv0_" || prefix == "bv1_" || prefix == "bv2_" ||
         prefix == "bv3_" || prefix == "bv4_" || prefix == "bv5_" ||
         prefix == "bv6_" || prefix == "bv7_" || prefix == "bv8_" ||
         prefix == "bv9_" || prefix == "cv0_" || prefix == "cv1_" ||
         prefix == "cv2_" || prefix == "cv3_" || prefix == "cv4_" ||
         prefix == "cv5_" || prefix == "cv6_" || prefix == "cv7_")
            ? 0
            : 1;
    word.char_ids[char_id_type][col] = id;
    assert (id > 0);

    bool all_set = true;
    for (int i = 0; i < 32; i++)
      if (word.char_ids[0][i] == 0 || word.char_ids[1][i] == 0) {
        all_set = false;
        break;
      }
    if (all_set)
      for (int i = 0; i < 32; i++) {
        solver->add_observed_var (word.char_ids[0][i]);
        solver->add_observed_var (word.char_ids[1][i]);
      }

    // printf ("Debug: %s %d %d %d\n", key.c_str (), id, step, col);
  }
}
} // namespace SHA256

#endif