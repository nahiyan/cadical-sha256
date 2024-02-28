#include "../sha256.hpp"
#include "../state.hpp"
#include <cassert>
#include <regex>
#include <sstream>

namespace SHA256 {
void add_4bit_variables (string line, CaDiCaL::Solver *&solver) {
  auto &state = Propagator::state;

  istringstream iss (line);
  string key;
  int value;
  iss >> key >> value;

  // Determine the order
  if (key == "order") {
    state.order = value;
    // Since this is the last comment, set the operations
    state.set_operations ();

    printf ("Initial state:\n");
    state.hard_refresh ();
    state.print ();

    return;
  } else if (key == "zero_g") {
    state.zero_var_id = value;
    assert (value >= 0);
    for (int i = 0; i < 6; i++) {
      solver->add_observed_var (value + i);
      state.vars_info[value + i].identity.name = Zero;
    }
    return;
  }

  // Get the step
  regex pattern ("(.+_)(\\d+)_[fg]");
  smatch match;
  int step;
  string actual_prefix;
  if (regex_search (key, match, pattern)) {
    actual_prefix = match[1];
    step = stoi (match[2].str ());
  } else {
    // printf ("Warning: Failed to load IDs from %s\n", key.c_str ());
    return;
  }

  // Determine the block
  bool is_f = key.back () == 'f';

  // Pair the prefixes with the words
  vector<pair<string, Word &>> prefix_pairs = {
      {"A_", state.steps[step].a},
      {"E_", state.steps[step].e},
      {"W_", state.steps[step].w},
      {"s0_", state.steps[step].s0},
      {"s1_", state.steps[step].s1},
      {"sigma0_", state.steps[step].sigma0},
      {"sigma1_", state.steps[step].sigma1},
      {"maj_", state.steps[step].maj},
      {"if_", state.steps[step].ch},
      {"T_", state.steps[step].t},
      {"K_", state.steps[step].k},
      {"add.W.r0_", state.steps[step].add_w_r[0]},
      {"add.W.r1_", state.steps[step].add_w_r[1]},
      {"add.T.r0_", state.steps[step].add_t_r[0]},
      {"add.T.r1_", state.steps[step].add_t_r[1]},
      {"add.E.r0_", state.steps[step].add_e_r[0]},
      {"add.A.r0_", state.steps[step].add_a_r[0]},
      {"add.A.r1_", state.steps[step].add_a_r[1]},
  };

  for (auto &pair : prefix_pairs) {
    auto &word = pair.second;
    string prefixes[] = {pair.first, 'D' + pair.first};

    for (auto &prefix : prefixes) {
      if (prefix != actual_prefix)
        continue;

      VariableName var_name = Unknown;
      if (prefix == "A_")
        var_name = A;
      else if (prefix == "E_")
        var_name = E;
      else if (prefix == "W_")
        var_name = W;
      else if (prefix == "s0_")
        var_name = sigma0;
      else if (prefix == "s1_")
        var_name = sigma1;
      else if (prefix == "sigma0_")
        var_name = Sigma0;
      else if (prefix == "sigma1_")
        var_name = Sigma1;
      else if (prefix == "maj_") {
        var_name = Maj;
      } else if (prefix == "if_")
        var_name = Ch;
      else if (prefix == "T_")
        var_name = T;
      else if (prefix == "K_")
        var_name = K;
      else if (prefix == "add.W.r0_")
        var_name = add_W_lc;
      else if (prefix == "add.W.r1_")
        var_name = add_W_hc;
      else if (prefix == "add.T.r0_")
        var_name = add_T_lc;
      else if (prefix == "add.T.r1_")
        var_name = add_T_hc;
      else if (prefix == "add.E.r0_")
        var_name = add_E_lc;
      else if (prefix == "add.A.r0_")
        var_name = add_A_lc;
      else if (prefix == "add.A.r1_")
        var_name = add_A_hc;
      if (prefix == "DA_")
        var_name = DA;
      else if (prefix == "DE_")
        var_name = DE;
      else if (prefix == "DW_")
        var_name = DW;
      else if (prefix == "Ds0_")
        var_name = Dsigma0;
      else if (prefix == "Ds1_")
        var_name = Dsigma1;
      else if (prefix == "Dsigma0_")
        var_name = DSigma0;
      else if (prefix == "Dsigma1_")
        var_name = DSigma1;
      else if (prefix == "Dmaj_") {
        var_name = DMaj;
      } else if (prefix == "Dif_")
        var_name = DCh;
      else if (prefix == "DT_")
        var_name = DT;
      else if (prefix == "DK_")
        var_name = DK;
      else if (prefix == "Dadd.W.r0_")
        var_name = Dadd_W_lc;
      else if (prefix == "Dadd.W.r1_")
        var_name = Dadd_W_hc;
      else if (prefix == "Dadd.T.r0_")
        var_name = Dadd_T_lc;
      else if (prefix == "Dadd.T.r1_")
        var_name = Dadd_T_hc;
      else if (prefix == "Dadd.E.r0_")
        var_name = Dadd_E_lc;
      else if (prefix == "Dadd.A.r0_")
        var_name = Dadd_A_lc;
      else if (prefix == "Dadd.A.r1_")
        var_name = Dadd_A_hc;
      assert (var_name >= Unknown && var_name <= Dadd_A_hc);

      if (prefix[0] == 'D')
        word.chars = string (32, '?');

      // Add the IDs
      for (int i = 0, id = value, id2 = value; i < 32;
           i++, id++, id2 += 4) {
        if (prefix[0] == 'D') {
          word.char_ids[i] = id2;
          for (int j = 0; j < 4; j++)
            state.vars_info[id2 + j] = {&word, step, i, var_name};
          assert (id == value ? state.vars_info[id2].identity.col == 0
                              : true);
        } else if (is_f) {
          word.ids_f[i] = id;
          state.vars_info[id] = {&word, step, i, var_name};
        } else {
          word.ids_g[i] = id;
          state.vars_info[id] = {&word, step, i, var_name};
        }
      }

      // Add to observed vars
      if (word.ids_f[0] != 0 && word.ids_g[0] != 0 && word.char_ids[0] != 0)
        for (int i = 0; i < 32; i++) {
          for (int j = 0; j < 4; j++)
            solver->add_observed_var (word.char_ids[i] + j);
        }
    }
  }
}
} // namespace SHA256