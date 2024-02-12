#include "sha256.hpp"
#include "1_bit/2_bit.hpp"
#include "1_bit/encoding.hpp"
#include "1_bit/propagate.hpp"
#include "2_bit.hpp"
#include "4_bit/2_bit.hpp"
#include "4_bit/differential.hpp"
#include "4_bit/encoding.hpp"
#include "4_bit/propagate.hpp"
#include "lru_cache.hpp"
#include "state.hpp"
#include "strong_propagate.hpp"
#include "tests.hpp"
#include "types.hpp"
#include "util.hpp"
#include <cassert>
#include <climits>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>
#include <string>

using namespace SHA256;

State Propagator::state = State ();
uint64_t prop_counter = 0;
uint64_t block_counter = 0;
uint64_t branch_counter = 0;
Stats Propagator::stats = Stats{0, 0, 0, 0};

Propagator::Propagator (CaDiCaL::Solver *solver) {
#ifndef NDEBUG
  run_tests ();
#endif
  this->solver = solver;
  solver->connect_external_propagator (this);
  printf ("Connected!\n");
  state.current_trail.push_back (std::vector<int> ());
  // load_prop_rules ();
  // load_two_bit_rules ();

#ifdef LOGGING
  printf ("Logging is enabled!\n");
#endif
}

void Propagator::parse_comment_line (string line,
                                     CaDiCaL::Solver *&solver) {
#if IS_4BIT
  add_4bit_variables (line, solver);
#else
  add_1bit_variables (line, solver);
#endif
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
  Timer timer (&stats.total_cb_time);
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

  // Remove reasons that no longer hold
  for (auto &p_lit : propagation_lits) {
    auto reason_it = reasons.find (p_lit);
    if (reason_it == reasons.end ())
      continue;

    // Remove reason if it doesn't hold anymore
    for (auto &lit : reason_it->second.antecedent) {
      auto value = state.partial_assignment.get (abs (lit));
      if (value == LIT_UNDEF) {
        reasons.erase (reason_it);
        break;
      }
    }
  }
}

void Propagator::notify_new_decision_level () {
  state.current_trail.push_back (std::vector<int> ());
}

string add_masks[4] = {".+.++", "+..+", "+++", "+...++"};
int add_input_sizes[4] = {4, 3, 2, 5};
// Strong propagate (through branching) words by taking information inside
// the addition equation
cache::lru_cache<string, pair<string, string>>
    strong_propagate_cache (100e3);
inline void strong_propagate_and_branch_1bit (State &state,
                                              list<int> &decision_lits) {
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
            for (int k = 0; k < 3; k++) {
              if (values[k] == 0)
                continue;
              if (state.partial_assignment.get (ids[k]) == LIT_UNDEF)
                continue;
              int lit = values[k] * ids[k];
              decision_lits.push_back (lit);
            }

            if (!decision_lits.empty ())
              return;
          }
      }

      // printf ("Step %2d (After), %d:  ", step_i, op_id);
      // for (auto &chars : words_chars)
      //   cout << chars << " ";
      // cout << endl;
    }
}

int Propagator::cb_decide () {
  Timer time (&stats.total_cb_time);

  if (decision_lits.empty ())
    return 0;
  int &lit = decision_lits.front ();
  decision_lits.pop_front ();
  stats.decisions_count++;
  // printf ("Debug: decision %d\n", lit);

  return lit;
}

inline void Propagator::custom_propagate () {
  state.soft_refresh ();
#if IS_4BIT
  custom_4bit_propagate (state, propagation_lits, reasons);
#else
  custom_1bit_propagate (state, propagation_lits, reasons);
#endif
}

inline bool Propagator::custom_block () {
  state.soft_refresh ();
#if IS_4BIT
  custom_4bit_block (state, two_bit);
#else
  custom_1bit_block (state, two_bit);
#endif

  // Collect all the equations
  two_bit.equations.clear ();
  two_bit.eq_freq.clear ();
  set<uint32_t> eq_vars;
  for (auto op_id = 0; op_id < 10; op_id++)
    for (auto step_i = 0; step_i < state.order; step_i++)
      for (auto pos = 0; pos < 32; pos++)
        for (auto &eq : two_bit.eqs_by_op[op_id][step_i][pos]) {
          // Check if the antecedent is still valid
          bool skip = false;
          for (auto &lit : eq.antecedent) {
            auto value = state.partial_assignment.get (abs ((int) lit));
            if (value == LIT_UNDEF ||
                value != (lit > 0 ? LIT_FALSE : LIT_TRUE)) {
              skip = true;
              continue;
            }
          }
          if (skip)
            continue;

          assert (!eq.antecedent.empty ());

          two_bit.equations.insert (eq);
          eq_vars.insert (eq.char_ids[0]);
          eq_vars.insert (eq.char_ids[1]);
        }

  if (two_bit.equations.empty ())
    return false;
  assert (!eq_vars.empty ());

  // Form the augmented matrix
  // Used to map the augmented matrix variable IDs
  two_bit.aug_mtx_var_map.clear ();
  int id = 0;
  for (auto &var : eq_vars)
    two_bit.aug_mtx_var_map[var] = id++;

  auto confl_equations = check_consistency (two_bit.equations, false);
  bool is_consistent = confl_equations.empty ();
  if (is_consistent)
    return false;

  // Block inconsistencies
  assert (external_clauses.empty ());
  block_inconsistency (two_bit, state.partial_assignment, external_clauses);
  // Keep only the shortest clause
  assert (!external_clauses.empty ());
  // printf ("Blocking clauses count: %ld\n", external_clauses.size ());
  int shortest_index = -1, shortest_length = INT_MAX;
  for (int i = 0; i < int (external_clauses.size ()); i++) {
    int size = external_clauses[i].size ();
    if (size >= shortest_length)
      continue;

    shortest_length = size;
    shortest_index = i;
  }
  auto shortest_clause = external_clauses[shortest_index];
  // printf ("Shortest clause length: %ld\n", shortest_clause.size ());
  // if (shortest_clause.size () > 20) {
  //   external_clauses.clear ();
  //   return false;
  // }

  assert (!shortest_clause.empty ());
  external_clauses.clear ();
  external_clauses.push_back (shortest_clause);
  for (auto &lit : shortest_clause)
    assert (state.partial_assignment.get (abs (lit)) ==
            (lit > 0 ? LIT_FALSE : LIT_TRUE));
  printf ("Blocking clause: ");
  print (shortest_clause);

  return true;
}

int Propagator::cb_propagate () {
  Timer time (&stats.total_cb_time);
  if (!propagation_lits.empty ())
    goto PROVIDE_LIT;

#if CUSTOM_PROP
  // if (++prop_counter % 20 == 0)
  custom_propagate ();
#endif

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

    // assert (reason.differential.inputs.size () > 0);
    // assert (reason.differential.outputs.size () > 0);
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
    // printf ("Propagation: %s -> %s\n", reason.differential.inputs.c_str
    // (),
    //         reason.differential.outputs.c_str ());
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

#if CUSTOM_BRANCHING
  if (decision_lits.empty ())
#if IS_4BIT
    strong_propagate_and_branch_4bit (state, decision_lits);
#else
    strong_propagate_and_branch_1bit (state, decision_lits);
#endif
    // custom_branch ();
#endif

  if (!external_clauses.empty ())
    return true;

#if CUSTOM_BLOCKING
  // if (++block_counter % 20 != 0)
  //   return false;

  // Check for 2-bit inconsistencies here
  return custom_block ();
#else
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

inline void Propagator::custom_branch () {
  state.soft_refresh ();

  auto rand_ground_x = [] (list<int> &decision_lits, Word &word, int &j) {
    srand (clock () + j);
    if (rand () % 2 == 0) {
      // u
      decision_lits.push_back (-(word.char_ids[j] + 0));
      // decision_lits.push_back ((word.char_ids[j] + 1));
      decision_lits.push_back (-(word.char_ids[j] + 2));
      decision_lits.push_back (-(word.char_ids[j] + 3));
    } else {
      // n
      decision_lits.push_back (-(word.char_ids[j] + 0));
      decision_lits.push_back (-(word.char_ids[j] + 1));
      // decision_lits.push_back ((word.char_ids[j] + 2));
      decision_lits.push_back (-(word.char_ids[j] + 3));
    }
  };

  auto ground_xnor = [] (list<int> &decision_lits, Word &word, int &j) {
    // decision_lits.push_back ((word.char_ids[j] + 0));
    decision_lits.push_back (-(word.char_ids[j] + 1));
    decision_lits.push_back (-(word.char_ids[j] + 2));
    // decision_lits.push_back ((word.char_ids[j] + 3));
  };

  // Stage 1
  for (int i = state.order - 1; i >= 0; i--) {
    auto &w = state.steps[i].w;
    for (int j = 0; j < 32; j++) {
      auto &c = w.chars[j];
      // Impose '-' for '?'
      if (c == '?') {
        ground_xnor (decision_lits, w, j);
        return;
      } else if (c == 'x') {
        // Impose 'u' or 'n' for '?'
        rand_ground_x (decision_lits, w, j);
        return;
      }
    }
  }

  // Stage 2
  for (int i = -4; i < state.order; i++) {
    auto &a = state.steps[ABS_STEP (i)].a;
    auto &e = state.steps[ABS_STEP (i)].e;
    for (int j = 0; j < 32; j++) {
      auto &a_c = a.chars[j];
      auto &e_c = e.chars[j];
      if (a_c == '?') {
        ground_xnor (decision_lits, a, j);
        return;
      } else if (a_c == 'x') {
        rand_ground_x (decision_lits, a, j);
        return;
      } else if (e_c == '?') {
        ground_xnor (decision_lits, e, j);
        return;
      } else if (e_c == 'x') {
        rand_ground_x (decision_lits, e, j);
        return;
      }
    }
  }

  // Stage 3
  if (two_bit.equations.empty ())
    return;

  auto &pa = state.partial_assignment;
  for (auto &eq : two_bit.equations) {
    uint32_t base_ids[] = {eq.char_ids[0], eq.char_ids[1]};
    for (int x = 0; x < 2; x++) {
      srand (clock () + x);
      if (pa.get (base_ids[x] + 0) != LIT_FALSE &&
          pa.get (base_ids[x] + 1) == LIT_FALSE &&
          pa.get (base_ids[x] + 2) == LIT_FALSE &&
          pa.get (base_ids[x] + 3) != LIT_FALSE) {
        if (rand () % 2 == 0)
          decision_lits.push_back (-(base_ids[x] + 0));
        else
          decision_lits.push_back (-(base_ids[x] + 3));
        return;
      }
    }
  }
}
