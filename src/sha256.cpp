#include "sha256.hpp"
#include "sha256_2_bit.hpp"
#include "sha256_propagate.hpp"
#include "sha256_state.hpp"
#include "sha256_tests.hpp"
#include "sha256_util.hpp"
#include <cassert>
#include <climits>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>
#include <string>

#define CUSTOM_BRANCHING false
#define BLOCK_INCONS true

using namespace SHA256;

int Propagator::order = 0;
State Propagator::state = State ();
uint64_t counter = 0;
uint64_t block_counter = 0;
Stats Propagator::stats = Stats{0, 0, 0, 0};

// void print_reason (Reason &reason, State &state) {
//   auto &pa = state.partial_assignment;
//   cout << "Reason: " << reason.differential.first << " -> "
//        << reason.differential.second << endl;
//   cout << "Input variables:" << endl;
//   for (int i = 0; i < int (reason.input_ids.size ()); i++) {
//     printf ("%d. ", i);
//     for (auto &id : reason.input_ids[i])
//       printf ("%d(%d) ", id, pa.get (id));
//     printf ("\n");
//   }
//   cout << "Output variables:" << endl;
//   for (int i = 0; i < int (reason.output_ids.size ()); i++) {
//     printf ("%d. ", i);
//     for (auto &id : reason.output_ids[i])
//       printf ("%d(%d) ", id, pa.get (id));
//     printf ("\n");
//   }
//   cout << "Antecedent: ";
//   for (auto &id : reason.antecedent)
//     printf ("%d ", id);
//   printf ("\n");
// }

Propagator::Propagator (CaDiCaL::Solver *solver) {
#ifndef NDEBUG
  run_tests ();
#endif
  this->solver = solver;
  solver->connect_external_propagator (this);
  printf ("Connected!\n");
  state.current_trail.push_back (std::vector<int> ());
  load_prop_rules ("prop-rules.db");
  load_two_bit_rules ("2-bit-rules.db");
#ifdef LOGGING
  printf ("Logging is enabled!\n");
#endif
}

void Propagator::parse_comment_line (string line,
                                     CaDiCaL::Solver *&solver) {
  istringstream iss (line);
  string key;
  int value;
  iss >> key >> value;

  // Determine the order
  if (key == "order") {
    order = value;
    state.order = order;
    // Since this is the last comment, set the operations
    state.set_operations ();

    printf ("Initial state:\n");
    state.hard_refresh ();
    state.print ();

    return;
  } else if (key == "zero_g") {
    state.zero_var_id = value;
    assert (value != 0);
    for (int i = 0; i < 6; i++)
      solver->add_observed_var (value + i);
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
      for (int i = 31, id = value, id2 = value; i >= 0;
           i--, id++, id2 += 4) {
        if (prefix[0] == 'D') {
          word.char_ids[i] = id2;
          for (int j = 0; j < 4; j++)
            state.vars_info[id2 + j] = {&word, i, step, var_name};
        } else if (is_f) {
          word.ids_f[i] = id;
          state.vars_info[id] = {&word, i, step, var_name};
        } else {
          word.ids_g[i] = id;
          state.vars_info[id] = {&word, i, step, var_name};
        }
      }

      // Add to observed vars
      if (word.ids_f[0] != 0 && word.ids_g[0] != 0 && word.char_ids[0] != 0)
        for (int i = 0; i < 32; i++) {
          solver->add_observed_var (word.ids_f[i]);
          solver->add_observed_var (word.ids_g[i]);
          for (int j = 0; j < 4; j++)
            solver->add_observed_var (word.char_ids[i] + j);
        }
    }
  }
}

void Propagator::notify_assignment (int lit, bool is_fixed) {
  // Timer timer (&stats.total_cb_time);
  if (is_fixed) {
    state.current_trail.front ().push_back (lit);
    state.vars_info[abs (lit)].is_fixed = true;
  } else
    state.current_trail.back ().push_back (lit);

  // Assign the variable in the partial assignment
  state.partial_assignment.set (lit);
  // printf ("Assign %d (%c%c) in level %ld\n", lit,
  //         solver->is_decision (lit) ? 'd' : 'p', is_fixed ? 'f' : 'l',
  //         state.current_trail.size () - 1);
}

void Propagator::notify_backtrack (size_t new_level) {
  // Timer timer (&stats.total_cb_time);
  while (state.current_trail.size () > new_level + 1) {
    // Unassign the variables that are removed from the trail
    auto &level = state.current_trail.back ();
    for (auto &lit : level) {
      state.partial_assignment.unset (lit);
      // printf ("Unassign %d (%ld)\n", lit, state.current_trail.size () -
      // 1);
    }
    state.current_trail.pop_back ();
  }
  assert (!state.current_trail.empty ());

  // Remove literals that no longer need to be propagated
  for (auto &p_lit : propagation_lits) {
    auto reason_it = reasons.find (p_lit);
    bool needs_propagation = true;

    if (reason_it == reasons.end ())
      needs_propagation = false;
    else
      for (auto &lit : reason_it->second.antecedent) {
        auto value = state.partial_assignment.get (abs (lit));
        bool unsatisfied = (value == LIT_TRUE && lit > 0) ||
                           (value == LIT_FALSE && lit < 0);
        if (value == LIT_UNDEF || unsatisfied) {
          needs_propagation = false;
          break;
        }
      }

    if (!needs_propagation) {
      if (reason_it != reasons.end ())
        reasons.erase (reason_it);
      // printf ("Erased reason for %d\n", p_lit);
    }
  }
}

void test_equations (vector<Equation> &equations);

void Propagator::notify_new_decision_level () {
  Timer timer (&stats.total_cb_time);

  state.current_trail.push_back (std::vector<int> ());
  counter++;

  // !Debug: 2-bit equations for 27-sfs
  // state.hard_refresh (true);
  // state.print ();
  // derive_two_bit_equations (two_bit, state);
  // test_equations (two_bit.equations[0]);
  // exit (0);

  // !Debug: Periodically print the state
  // if (counter % 100000 == 0) {
  //   printf ("Current state:\n");
  //   // state.hard_refresh (false);
  //   state.soft_refresh ();
  //   state.print ();
  // }
#if CUSTOM_BRANCHING
  custom_branch ();
#endif
}

int Propagator::cb_decide () {
  // Timer time (&stats.total_cb_time);
  if (decision_lits.empty ())
    return 0;
  int lit = decision_lits.front ();
  decision_lits.pop_front ();
  stats.decisions_count++;
  // printf ("Debug: decision %d\n", lit);

  return lit;
}

void Propagator::get_differential (OperationId op_id, int step_i,
                                   int bit_pos,
                                   vector<Differential> &diffs) {
  struct Operation {
    FunctionId function_id;
    SoftWord *operands;
    vector<Word *> outputs;
    int input_size, output_size;
    string mask;
  };

  auto get_operation = [this] (OperationId id, int step_i) {
    auto &ops = state.operations[step_i];
    auto &step = state.steps[step_i];
    switch (id) {
    case op_s0:
      assert (step_i >= 16);
      return Operation{xor3, ops.s0.inputs, {&step.s0}, 3, 1, "+++."};
    case op_s1:
      assert (step_i >= 16);
      return Operation{xor3, ops.s1.inputs, {&step.s1}, 3, 1, "+++."};
    case op_sigma0:
      return Operation{xor3,  ops.sigma0.inputs, {&step.sigma0}, 3, 1,
                       "+++."};
    case op_sigma1:
      return Operation{xor3,  ops.sigma1.inputs, {&step.sigma1}, 3, 1,
                       "+++."};
    case op_maj:
      return Operation{maj, ops.maj.inputs, {&step.maj}, 3, 1, "+++."};
    case op_ch:
      return Operation{ch, ops.ch.inputs, {&step.ch}, 3, 1, "+++."};
    case op_add_w:
      assert (step_i >= 16);
      return Operation{add,
                       ops.add_w.inputs,
                       {&step.add_w_r[1], &step.add_w_r[0], &step.w},
                       6,
                       3,
                       ".+.+....+"};
    case op_add_a:
      return Operation{add,
                       ops.add_a.inputs,
                       {&step.add_a_r[1], &step.add_a_r[0],
                        &state.steps[ABS_STEP (step_i)].a},
                       5,
                       3,
                       "+......+"};
    case op_add_e:
      return Operation{add,
                       ops.add_e.inputs,
                       {&state.zero_word, &step.add_e_r[0],
                        &state.steps[ABS_STEP (step_i)].e},
                       3,
                       3,
                       "++...+"};
    case op_add_t:
      return Operation{add,
                       ops.add_t.inputs,
                       {&step.add_t_r[1], &step.add_t_r[0], &step.t},
                       7,
                       3,
                       "+...+....+"};
    default:
      // This condition shouldn't be met
      assert (false);
      return Operation{};
    }
  };

  auto operation = get_operation (op_id, step_i);
  FunctionId &function_id = operation.function_id;
  SoftWord *input_words = operation.operands;
  vector<Word *> output_words = operation.outputs;
  int input_size = operation.input_size,
      output_size = operation.output_size;
  auto function = function_id == maj    ? maj_
                  : function_id == ch   ? ch_
                  : function_id == xor3 ? xor_
                                        : add_;
  auto &i = step_i;
  auto &j = bit_pos;

  Differential diff;
  diff.function = function;
  diff.operation_id = op_id;
  diff.step_index = i;
  diff.bit_pos = j;
  diff.mask = operation.mask;

  for (int x = 0; x < input_size; x++) {
    auto &input_word = input_words[x];
    assert (input_word.chars[j] != NULL);
    diff.inputs += *(input_word.chars[j]);
    diff.char_base_ids.first.push_back (input_word.char_ids[j]);

    diff.table_values.first.push_back (gc_values (*input_word.chars[j]));
    assert (diff.table_values.first[x] != 0);
  }
  assert (int (diff.inputs.size ()) == input_size);
  assert (int (diff.char_base_ids.first.size ()) == input_size);
  assert (int (diff.table_values.first.size ()) == input_size);

  for (int x = 0; x < output_size; x++) {
    auto &output_word = output_words[x];
    diff.outputs += output_word->chars[j];
    diff.char_base_ids.second.push_back (output_word->char_ids[j]);

    diff.table_values.second.push_back (gc_values (output_word->chars[j]));
    assert (diff.table_values.second[x] != 0);
  }
  assert (int (diff.outputs.size ()) == output_size);
  assert (int (diff.char_base_ids.second.size ()) == output_size);
  assert (int (diff.table_values.second.size ()) == output_size);

  diffs.push_back (diff);
}

void Propagator::custom_propagate () {
  state.soft_refresh ();
  while (true) {
    auto &step_i = get<1> (state.last_marked_op);
    if (get<1> (state.last_marked_op) == -1)
      return;
    auto &op_id = get<0> (state.last_marked_op);
    auto &bit_pos = get<2> (state.last_marked_op);
    vector<Differential> diffs;
    get_differential (op_id, step_i, bit_pos, diffs);
    state.last_marked_op = {op_s0, -1, -1};
    if (diffs.empty ())
      return;
    for (auto &diff_ : diffs) {
      Reason reason;
      reason.differential = diff_;
      auto &diff = reason.differential;
      assert (!diff.inputs.empty ());

      string prop_output =
          otf_propagate (diff.function, diff.inputs, diff.outputs);
      if (diff.outputs == prop_output)
        continue;

      // Construct the antecedent with inputs
      int const_zeroes_count = 0;
      for (unsigned long x = 0; x < diff.inputs.size (); x++) {
        if (diff.inputs[x] == '?')
          continue;

        // Count the const zeroes
        bool is_const_zero = false;
        if (diff.char_base_ids.first[x] == state.zero_var_id + 2) {
          const_zeroes_count++;
          is_const_zero = true;
          continue;
        }

        // Add lits
        auto &base_id = diff.char_base_ids.first[x];
        for (int y = 0; y < 4; y++) {
          if ((diff.table_values.first[x] >> y & 1) == 1)
            continue;
          assert (state.partial_assignment.get (base_id + y) != LIT_UNDEF);
          reason.antecedent.push_back (base_id + y);
        }
      }

      if (reason.antecedent.empty ())
        continue;

      // Construct the antecedent with outputs
      vector<int> prop_lits;
      for (unsigned long x = 0; x < diff.outputs.size (); x++) {
        // Ignore the high carry output if addends can't add up to >= 4
        if (diff.function == add_ && x == 0 &&
            (diff.inputs.size () - const_zeroes_count) < 4)
          continue;

        if (diff.char_base_ids.second[x] == state.zero_var_id + 2)
          continue;

        auto &table_values = diff.table_values.second[x];
        bool has_output_antecedent = false;
        {
          if (diff.outputs[x] != '?') {
            assert (table_values != 15);
            for (int y = 0; y < 4; y++) {
              auto &base_id = diff.char_base_ids.second[x];
              if ((table_values >> y & 1) == 1)
                continue;
              reason.antecedent.push_back (base_id + y);
              assert (state.partial_assignment.get (base_id + y) !=
                      LIT_UNDEF);
              has_output_antecedent = true;
            }
          }
        }
        assert (diff.outputs[x] != '?' ? has_output_antecedent : true);

        if (prop_output[x] == '?' || prop_output[x] == '#')
          continue;

        auto prop_table_values = gc_values (prop_output[x]);
        for (int y = 0; y < 4; y++) {
          int id = diff.char_base_ids.second[x] + y;

          uint8_t value = prop_table_values >> y & 1;
          if (value == 1)
            continue;

          if (state.partial_assignment.get (id) != LIT_UNDEF)
            continue;

          int sign = value == 1 ? 1 : -1;
          int lit = sign * id;

          propagation_lits.push_back (lit);
          prop_lits.push_back (lit);
        }
      }

      diff.outputs = prop_output;

      for (auto &lit : prop_lits)
        reasons[lit] = reason;
    }

    if (!propagation_lits.empty ())
      return;
  }
}

bool Propagator::custom_block () {
  state.soft_refresh ();
  for (int op_id = 0; op_id < 10; op_id++)
    for (int step_i = 0; step_i < state.order; step_i++)
      for (int bit_pos = 0; bit_pos < 32; bit_pos++) {
        auto &marked_op =
            state.marked_operations[(OperationId) op_id][step_i][bit_pos];
        if (!marked_op)
          continue;
        vector<Differential> diffs;
        get_differential ((OperationId) op_id, step_i, bit_pos, diffs);
        marked_op = false;
        if (diffs.empty ())
          break;
        for (auto &diff : diffs) {
          auto char_base_ids = diff.char_base_ids.first;
          char_base_ids.insert (char_base_ids.end (),
                                diff.char_base_ids.second.begin (),
                                diff.char_base_ids.second.end ());
          assert (diff.char_base_ids.first.size () +
                      diff.char_base_ids.second.size () ==
                  char_base_ids.size ());
          auto &op_id = diff.operation_id;
          auto &step_i = diff.step_index;
          auto &pos = diff.bit_pos;

          // Replace the equations for this particular spot
          auto &op_eqs = two_bit.eqs_by_op[op_id][step_i][pos];
          op_eqs.clear ();
          auto equations =
              otf_2bit_eqs (diff.function, diff.inputs, diff.outputs,
                            char_base_ids, diff.mask);
          string all_chars = diff.inputs + diff.outputs;
          for (auto &equation : equations) {
            // Process inputs
            int const_zeroes_count = 0;
            for (int input_i = 0;
                 input_i < int (diff.char_base_ids.first.size ());
                 input_i++) {
              if (diff.inputs[input_i] == '?')
                continue;

              bool is_const_zero = false;
              auto &base_id = diff.char_base_ids.first[input_i];
              if (base_id == state.zero_var_id + 2) {
                const_zeroes_count++;
                is_const_zero = true;
                continue;
              }

              uint8_t values = gc_values (diff.inputs[input_i]);
              for (int k = 0; k < 4; k++) {
                if ((values >> k & 1) == 1)
                  continue;

                uint32_t var = base_id + k;
                assert (state.partial_assignment.get (var) == LIT_FALSE);
                equation.antecedent.push_back (var);
              }
            }

            // Process outputs
            for (int output_i = 0;
                 output_i < int (diff.char_base_ids.second.size ());
                 output_i++) {
              if (diff.outputs[output_i] == '?')
                continue;

              // Ignore the high carry output if addends can't add up to >=
              // 4
              if (diff.function == add_ && output_i == 0 &&
                  (diff.inputs.size () - const_zeroes_count) < 4)
                continue;

              if (diff.char_base_ids.second[output_i] ==
                  state.zero_var_id + 2)
                continue;

              auto &base_id = diff.char_base_ids.second[output_i];
              if (base_id == state.zero_var_id + 2)
                continue;

              uint8_t values = gc_values (diff.outputs[output_i]);
              for (int k = 0; k < 4; k++) {
                if ((values >> k & 1) == 1)
                  continue;

                uint32_t var = base_id + k;
                assert (state.partial_assignment.get (var) == LIT_FALSE);
                equation.antecedent.push_back (var);
              }
            }
            assert (!equation.antecedent.empty ());
            op_eqs.push_back (equation);
          }
        }
      }

  // Collect all the equations
  two_bit.eqs[0].clear ();
  set<uint32_t> eq_vars;
  for (auto op_id = 0; op_id < 10; op_id++)
    for (auto step_i = 0; step_i < state.order; step_i++)
      for (auto pos = 0; pos < 32; pos++)
        for (auto &eq : two_bit.eqs_by_op[op_id][step_i][pos]) {
          // Check if the antecedent is still valid
          bool skip = false;
          for (auto &lit : eq.antecedent)
            if (state.partial_assignment.get (lit) != LIT_FALSE)
              skip = true;
          if (skip)
            continue;

          assert (!eq.antecedent.empty ());

          two_bit.eqs[0].insert (eq);
          eq_vars.insert (eq.char_ids[0]);
          eq_vars.insert (eq.char_ids[1]);
        }

  if (two_bit.eqs[0].empty ())
    return false;

  assert (!eq_vars.empty ());

  // Form the augmented matrix
  // Used to map the augmented matrix variable IDs
  two_bit.aug_mtx_var_map.clear ();
  int id = 0;
  for (auto &var : eq_vars)
    two_bit.aug_mtx_var_map[var] = id++;

  bool has_clause = false;
  // TODO: Add support for 2 blocks
  for (int block_index = 0; block_index < 1; block_index++) {
    auto confl_equations =
        check_consistency (two_bit.eqs[block_index], false);
    bool is_consistent = confl_equations.empty ();
    if (is_consistent)
      continue;

    // Block inconsistencies
    block_inconsistency (two_bit, state.partial_assignment,
                         external_clauses, block_index);
    has_clause = true;
    break;
  }
  // Keep only the shortest clause
  if (has_clause) {
    assert (!external_clauses.empty ());
    int shortest_index = -1, shortest_length = INT_MAX;
    for (int i = 0; i < int (external_clauses.size ()); i++) {
      int size = external_clauses[i].size ();
      if (size >= shortest_length)
        continue;

      shortest_length = size;
      shortest_index = i;
    }
    auto clause = external_clauses[shortest_index];
    assert (!clause.empty ());
    external_clauses.clear ();
    external_clauses.push_back (clause);
    printf ("Blocking clause: ");
    print (clause);
  }

  return has_clause;
}

int Propagator::cb_propagate () {
  Timer time (&stats.total_cb_time);
  if (!propagation_lits.empty ())
    goto PROVIDE_LIT;

  // if (counter % 20 == 0)
  custom_propagate ();

  if (propagation_lits.empty ())
    return 0;

PROVIDE_LIT:
  int &lit = propagation_lits.back ();
  assert (lit != 0);

  // If reason doesn't exist, skip propagation
  auto reason_it = reasons.find (lit);
  if (reason_it == reasons.end ()) {
    propagation_lits.pop_back ();
    return 0;
  }

  // printf ("Debug: propagate %d (var %d)\n", lit,
  //         state.var_info[abs (lit)].name);
  propagation_lits.pop_back ();
  assert (reason_it->second.antecedent.size () > 0);

  if (state.partial_assignment.get (abs (lit)) != LIT_UNDEF)
    return 0;

  return lit;
}

int Propagator::cb_add_reason_clause_lit (int propagated_lit) {
  // Timer time (&stats.total_cb_time);

  if (reason_clause.size () == 0 &&
      reasons.find (propagated_lit) == reasons.end ())
    return 0;

  if (reason_clause.size () == 0) {
    // Generate the reason clause
    auto reasons_it = reasons.find (propagated_lit);
    assert (reasons_it != reasons.end ());
    Reason reason = reasons_it->second;
    reasons.erase (reasons_it); // Consume the reason
    stats.reasons_count++;

    // printf ("Asked for reason of %d (var %d)\n", propagated_lit,
    //         state.var_info[abs (propagated_lit)].name);

    // print_reason (reason, state);

    assert (reason.differential.inputs.size () > 0);
    assert (reason.differential.outputs.size () > 0);
    assert (reason.antecedent.size () > 0);

    // Populate the reason clause
    for (auto &lit : reason.antecedent) {
      // Sanity check
      assert (state.partial_assignment.get (abs (lit)) != LIT_UNDEF);
      assert (state.partial_assignment.get (abs (lit)) == LIT_TRUE
                  ? lit < 0
                  : lit > 0);
      reason_clause.push_back (lit);
    }
    reason_clause.push_back (propagated_lit);

    // print_reason (reason, state);
    printf ("Reason clause: ");
    for (auto &lit : reason_clause)
      printf ("%d ", lit);
    printf ("\n");
  }

  assert (reason_clause.size () > 0);
  int lit = reason_clause.back ();
  reason_clause.pop_back ();
  // printf ("Debug: providing reason clause %d: %d (%d); remaining %ld\n",
  //         propagated_lit, lit, state.partial_assignment.get (abs (lit)),
  //         reason_clause.size ());

  return lit;
}

bool Propagator::cb_has_external_clause () {
  Timer time (&stats.total_cb_time);

#if BLOCK_INCONS
  // if (++block_counter % 20 != 0)
  //   return false;

  // Check for 2-bit inconsistencies here
  return custom_block ();
#else
  if (!external_clauses.empty ())
    return true;
  return false;
#endif
}

int Propagator::cb_add_external_clause_lit () {
  // Timer timer (&stats.total_cb_time);
  if (external_clauses.empty ())
    return 0;

  auto &clause = external_clauses.back ();
  assert (!clause.empty ());
  int lit = clause.back ();
  auto value = state.partial_assignment.get (abs (lit));
  // printf ("Debug: gave EC lit %d (%d) %ld remaining\n", lit, value,
  //         clause.size () - 1);

  // Pop clause and remove if empty
  clause.pop_back ();
  if (clause.empty ()) {
    external_clauses.pop_back ();
    stats.clauses_count++;
    // printf ("Debug: EC ended\n");
  }

  // Sanity check for blocking clauses
  assert (lit < 0   ? value == LIT_TRUE
          : lit > 0 ? value == LIT_FALSE
                    : value != LIT_UNDEF);

  return lit;
}

// void Propagator::custom_branch () {
//   if (counter % 20 != 0)
//     return;
//   if (!decision_lits.empty ())
//     return;

//   // state.refresh (false);

//   // Refresh the state
//   state.soft_refresh ();

//   auto rand_ground_x = [] (list<int> &decision_lits, Word &word, int &j)
//   {
//     srand (clock () + j);
//     if (rand () % 2 == 0) {
//       // u
//       decision_lits.push_back (-(word.char_ids[j] + 0));
//       decision_lits.push_back ((word.char_ids[j] + 1));
//       decision_lits.push_back (-(word.char_ids[j] + 2));
//       decision_lits.push_back (-(word.char_ids[j] + 3));
//     } else {
//       // n
//       decision_lits.push_back (-(word.char_ids[j] + 0));
//       decision_lits.push_back (-(word.char_ids[j] + 1));
//       decision_lits.push_back ((word.char_ids[j] + 2));
//       decision_lits.push_back (-(word.char_ids[j] + 3));
//     }
//   };
//   auto ground_xnor = [] (list<int> &decision_lits, Word &word, int &j) {
//     decision_lits.push_back ((word.char_ids[j] + 0));
//     decision_lits.push_back (-(word.char_ids[j] + 1));
//     decision_lits.push_back (-(word.char_ids[j] + 2));
//     decision_lits.push_back ((word.char_ids[j] + 3));
//   };

//   // Stage 1
//   for (int i = order - 1; i >= 0; i--) {
//     auto &w = state.steps[i].w;
//     for (int j = 0; j < 32; j++) {
//       auto &c = w.chars[j];
//       // Impose '-' for '?'
//       if (c == '?') {
//         ground_xnor (decision_lits, w, j);
//         return;
//       } else if (c == 'x') {
//         // Impose 'u' or 'n' for '?'
//         rand_ground_x (decision_lits, w, j);
//         return;
//       }
//     }
//   }

//   // printf ("Stage 2\n");

//   // Stage 2
//   for (int i = -4; i < order; i++) {
//     auto &a = state.steps[ABS_STEP (i)].a;
//     auto &e = state.steps[ABS_STEP (i)].e;
//     for (int j = 0; j < 32; j++) {
//       auto &a_c = a.chars[j];
//       auto &e_c = e.chars[j];
//       if (a_c == '?') {
//         ground_xnor (decision_lits, a, j);
//         return;
//       } else if (a_c == 'x') {
//         rand_ground_x (decision_lits, a, j);
//         return;
//       } else if (e_c == '?') {
//         ground_xnor (decision_lits, e, j);
//         return;
//       } else if (e_c == 'x') {
//         rand_ground_x (decision_lits, e, j);
//         return;
//       }
//     }
//   }

//   // printf ("Stage 3\n");

//   // Stage 3
// #if BLOCK_INCONS == false
//   two_bit = TwoBit{};
//   derive_two_bit_equations (two_bit, state);
// #endif
//   for (auto &entry : two_bit.bit_constraints_count) {
//     uint32_t ids[] = {get<0> (entry.first), get<1> (entry.first),
//                       get<2> (entry.first)};
//     uint32_t values[] = {state.partial_assignment.get (ids[0]),
//                          state.partial_assignment.get (ids[1]),
//                          state.partial_assignment.get (ids[2])};
//     if (values[2] == LIT_FALSE) {
//       // Impose '-'
//       srand (clock ());
//       if (rand () % 2 == 0) {
//         decision_lits.push_back (ids[0]);
//         decision_lits.push_back (ids[1]);
//       } else {
//         decision_lits.push_back (-ids[0]);
//         decision_lits.push_back (-ids[1]);
//       }
//       // printf ("Stage 3: guess\n");
//       return;
//     }
//   }
// }

// !Debug
// void test_equations (vector<Equation> &equations, State &state) {
//   ifstream file ("equations.txt");
//   string line;
//   regex pattern ("Equation\\(x='(.*?)', y='(.*?)', diff=(.*?)\\)");
//   vector<Equation> found_equations;
//   vector<Equation> missing_equations;
//   while (getline (file, line)) {
//     smatch match;
//     if (regex_search (line, match, pattern)) {
//       if (match.size () == 4) {
//         string x = match[1];
//         string y = match[2];
//         int diff = stoi (match[3]);

//         bool found = false;
//         for (auto &equation : equations) {
//           VarIdentity *var_infos[2] = {
//               state.var_info[equation[0].diff_ids[0]].identity,
//               state.var_info[equation[1].diff_ids[0]].identity};
//           // TODO: Fix this
//           if (equation.diff == diff &&
//               ((equation.names[0] == x && equation.names[1] == y) ||
//                (equation.names[1] == x && equation.names[0] == y))) {
//             found_equations.push_back (equation);
//             found = true;
//           }
//         }

//         if (!found) {
//           Equation equation;
//           equation.names[0] = x;
//           equation.names[1] = y;
//           equation.diff = diff;
//           missing_equations.push_back (equation);
//         }
//       }
//     } else {
//       cout << "No match found." << endl;
//     }
//   }

//   cout << "Unmatched equations: "
//        << equations.size () - found_equations.size () << endl;
//   cout << endl;

//   cout << "Found " << found_equations.size () << " equations" << endl;
//   for (auto &equation : found_equations)
//     cout << equation.names[0] << " " << (equation.diff == 0 ? "=" :
//     "=/=")
//          << " " << equation.names[1] << endl;
//   cout << endl;

//   cout << "Missing " << missing_equations.size () << " equations" <<
//   endl; for (auto &equation : missing_equations)
//     cout << equation.names[0] << " " << (equation.diff == 0 ? "=" :
//     "=/=")
//          << " " << equation.names[1] << endl;
// }
