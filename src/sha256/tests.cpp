#include "tests.hpp"
#include "2_bit.hpp"
#include "2_bit_graph.hpp"
#include "NTL/mat_GF2.h"
#include "linear_propagate.hpp"
#include "propagate.hpp"
#include "sha256.hpp"
#include "state.hpp"
#include "util.hpp"
#include "wordwise_propagate.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <utility>

namespace SHA256 {
void test_int_diff () {
  assert (_word_diff ("0n0n001001u-1u1n01un010n01n00110") == 2955087584);
  assert (_word_diff ("nnnnn-nnnn--------nuu-----------") == 71301120);
  assert (_word_diff ("nnnnn-nnnA--------nuu-----------") == -1);
  assert (_word_diff ("--------------------------------") == 0);
  assert (_word_diff ("0n0n001001u") == 1409);
  assert (_word_diff ("u-n") == 3);
}

void test_adjust_constant () {
  assert (2196 == adjust_constant ("--xxxx-xx--x",
                                   adjust_constant ("--B--D-BBBB-", 1147)));
}

void test_is_congruent () {
  assert (true == is_congruent (2, 0, 2));
  assert (false == is_congruent (2, 1, 2));
  assert (true == is_congruent (16, 2, 2));
  assert (false == is_congruent (16, 1, 16));
}

void test_can_overflow () {
  assert (false == _can_overflow ({"v"}, {0}));
  assert (true == _can_overflow ({"vv"}, {0}));
  assert (false == _can_overflow ({"vv", "v"}, {0, 1}));
  assert (true == _can_overflow ({"vv", "v"}, {0, 0}));
  assert (true == _can_overflow ({"vv", "v", "v"}, {0, 0, 0}));
  assert (true == _can_overflow ({"vv", "v", "vv"}, {0, 0, 1}));
  assert (true == _can_overflow ({"vv", "v", "vv", "vv"}, {0, 0, 1, 1}));
  assert (true == _can_overflow ({"vv", "vv", "vv"}, {0, 0, 0}));
  assert (false == _can_overflow ({"vv", "vv", "v1"}, {0, 0, 0, 1}));
  assert (true ==
          _can_overflow ({"v", "vv", "v", "vv1", "vv"}, {0, 0, 1, 0, 0}));
}

void test_gen_vars () {
  {
    vector<string> expected = {
        "",  "vv1", "vv", "",   "v1", "vv", "v", "",   "1",
        "v", "v",   "v",  "vv", "vv", "vv", "v", "vv", "",
    };
    auto actual = gen_vars ({"-uxxu-xx1u---x-00x", "--?0-?0--u?A-???5-"});
    assert (actual == expected);
  }

  {
    vector<string> expected = {"v", "vv", "vv", "vv", "v",
                               "",  "v",  "v",  "",   ""};
    auto actual = gen_vars ({"x???xx1xx-"});
  }
}

void test_brute_force () {
  assert (brute_force ({"vv", "v"}, 2) == "vvv");
  assert (brute_force ({"vv", "v"}, 4) == "111");
  assert (brute_force ({"vv", "vv"}, 0, 3) == "vvvv");
  assert (brute_force ({"vv", "vv", "v1"}, 8) == "vvvvv");
  assert (brute_force ({"vv", "vvv"}, 0, -1, true) == "vvvvv");
  assert (brute_force ({"v", "vv", "v", "vv1", "vv"}, 4, -1, true) ==
          "0vvvvvvv");
}

void test_apply_grounding () {
  // TODO: Add tests
}
void test_wordwise_prop () {
  {
    vector<string> expected = {"--uunu-nx--x", "--u--n-B-BB-"};
    auto actual =
        wordwise_propagate ({"--xxxx-xx--x", "--B--D-BBBB-"}, 1147);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"-u-------uu-uu-u0u1--u-0-n---n0-"};
    auto actual = wordwise_propagate ({"-u-?-----uu-uu-u0u1?-u-0-n?--n0-"},
                                      1080902588);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"---nuu1ununnn-1unnnnnn-n--0-1---"};
    auto actual = wordwise_propagate ({"---nuu1ununnn-1uxnxnxn-x--0-1---"},
                                      4236772096);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"x-n-nn-xxn-u-u--uuuux-u---x-x---",
                               "-------B-n--u------D---n--BBu---"};
    auto actual = wordwise_propagate ({"x-x-xx-xxn-x-x--xxxxx-x---x-x---",
                                       "-------BDD--B------D---DD-BBBB--"},
                                      1411180832);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"xxxxxxu----n-unnnu-x--uxxxu-xxx-",
                               "DDDDD-n-nn--u-----D-u--DD-BBBB--"};
    auto actual = wordwise_propagate ({"xxxxxxx----x-xxxxx-x--uxxxx-xxx-",
                                       "DDDDD-D-nn--B-----D-B--DD-BBBB--"},
                                      725137662);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"----x-nx---n--n--nu--uunu-nx--x-",
                               "DDDD-nD-nn--u-----n--u--n-B-BB--"};
    auto actual = wordwise_propagate ({"----x-xx---x--x--xx--xxxx-xx--x-",
                                       "DDDD-DD-nn-Du-----D--B--D-BBBB--"},
                                      2151008502);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"--n-1u-----00--x1-n-x--n--------",
                               "un000unuuu110A5-11n-x0nn110-0nu1"};
    auto actual = wordwise_propagate ({"--n-1x-----00--x1-n-x--n--------",
                                       "un000unuuu110A5-11n-x0nn110-0nu1"},
                                      666942462);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"0nun1n--uu--n--nuuu0u--uu-uuuu0-"};
    auto actual = wordwise_propagate ({"0nun1x--ux--n--nxxu0x--ux-uuxu0-"},
                                      3434604988);
    assert (expected == actual);
  }

  // {
  //   vector<string> expected = {"xu-nnu--uxxu-xn1u---x-00x-u0-1--",
  //                              "---------?0-?0--u-A-???5-u------"};
  //   auto actual = wordwise_propagate
  //   ({"xx-nnx--uxxu-xx1u---x-00x-u0-1--",
  //                                      "---------?0-?0--u?A-???5-u---?--"},
  //                                     2896892384);
  //   assert (expected == actual);
  // }

  {
    vector<string> expected = {"x???xu1uu-"};
    auto actual = wordwise_propagate ({"x???xx1xx-"}, 70);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"-----------------------------x--",
                               "?????????????????????????????x--"};
    auto actual = wordwise_propagate ({"-----------------------------x--",
                                       "?????????????????????????????x--"},
                                      0);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"-----x--", "?????x--"};
    auto actual = wordwise_propagate ({"-----x--", "?????x--"}, 0);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"-----------------------------u--",
                               "-------------------------nuuuu--"};
    auto actual = wordwise_propagate ({"-----------------------------x--",
                                       "-------------------------nuuuu--"},
                                      0);
    assert (expected == actual);
  }

  // {
  //   vector<string> expected = {"---------------------unnnnnnnn--"};
  //   auto actual =
  //       wordwise_propagate ({"---------------------?nnxxnnnn--"}, 4);
  //   assert (expected == actual);
  // }

  {
    vector<string> expected = {"xxxuxxxxxxxxxxxu------xxxx------",
                               "--xxxxx--xx--xx----xxxx-xx------"};
    assert (_word_diff ("----n11-------un0---------------") == 4160815104);
    auto actual = wordwise_propagate (
        {"xxxuxxxxxxxxxxxu------xxxx------",
         "--xxxxx--xx--xx----xxxx-xx------"},
        _word_diff ("----n11-------un0---------------"));
    assert (expected == actual);
  }

  {
    vector<string> expected = {"-----------------------------x--",
                               "?????????????????????????????x--"};
    auto actual = wordwise_propagate ({"-----------------------------x--",
                                       "?????????????????????????????x--"},
                                      0);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"-----x--", "?????x--"};
    auto actual = wordwise_propagate ({"-----x--", "?????x--"}, 0);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"-----------------------------u--",
                               "-------------------------nuuuu--"};
    auto actual = wordwise_propagate ({"-----------------------------x--",
                                       "-------------------------nuuuu--"},
                                      0);
    assert (expected == actual);
  }

  // {
  //   vector<string> expected = {"---------------------unnnnnnnn--"};
  //   auto actual =
  //       wordwise_propagate ({"---------------------?nnxxnnnn--"}, 4);
  //   assert (expected == actual);
  // }

  {
    vector<string> expected = {"xxxuxxxxxxxxxxxu------xxxx------",
                               "--xxxxx--xx--xx----xxxx-xx------"};
    assert (_word_diff ("----n11-------un0---------------") == 4160815104);
    auto actual = wordwise_propagate (
        {"xxxuxxxxxxxxxxxu------xxxx------",
         "--xxxxx--xx--xx----xxxx-xx------"},
        _word_diff ("----n11-------un0---------------"));
    assert (expected == actual);
  }
}

void test_group_wordwise_prop () {
  test_int_diff ();
  test_adjust_constant ();
  test_is_congruent ();
  test_can_overflow ();
  test_gen_vars ();
  test_brute_force ();
  test_apply_grounding ();
  test_wordwise_prop ();
}

void test_rotate_word () {
  assert ((vector<int>{3, 4, 1, 2} == rotate_vec<int> ({1, 2, 3, 4}, 2)));
  assert ((vector<int>{0, 0, 1, 2} ==
           rotate_vec<int> ({1, 2, 3, 4}, 2, false)));
  {
    vector<char> expected_word = {'u', '1', '0', 'u', '1', '0', '1', 'u',
                                  '0', '-', '0', 'u', '1', '-', 'n', 'n',
                                  '-', 'n', '-', 'u', '-', '1', 'u', '-',
                                  '-', '-', '1', '1', 'u', 'n', '0', 'u'};
    assert (expected_word ==
            rotate_vec<char> ({'0', 'u', '1', '-', 'n', 'n', '-', 'n',
                               '-', 'u', '-', '1', 'u', '-', '-', '-',
                               '1', '1', 'u', 'n', '0', 'u', 'u', '1',
                               '0', 'u', '1', '0', '1', 'u', '0', '-'},
                              10));
  }
  {
    vector<char> expected_word = {0,   0,   0,   '0', 'u', '1', '-', 'n',
                                  'n', '-', 'n', '-', 'u', '-', '1', 'u',
                                  '-', '-', '-', '1', '1', 'u', 'n', '0',
                                  'u', 'u', '1', '0', 'u', '1', '0', '1'};
    assert (expected_word ==
            rotate_vec<char> ({'0', 'u', '1', '-', 'n', 'n', '-', 'n',
                               '-', 'u', '-', '1', 'u', '-', '-', '-',
                               '1', '1', 'u', 'n', '0', 'u', 'u', '1',
                               '0', 'u', '1', '0', '1', 'u', '0', '-'},
                              3, false));
  }
}

void test_otf_propagate () {
#if !IS_LI2024
  {
    auto result = otf_propagate (add_, "-0n10n", "???");
    assert (result.second == "5x-");
  }
  {
    auto result = otf_propagate (add_, "-1n51-75", "??1");
    assert (result.second == "D?1");
  }
  {
    auto result = otf_propagate (add_, "-0nu0uDD", "??1");
    assert (result.second == "011");
  }
  {
    auto result = otf_propagate (add_, "110?100", "1??");
    assert (result.first == "1101100");
    assert (result.second == "100");
  }
  {
    auto result = otf_propagate (add_, "-??", "0?-");
    assert (result.second == "0?-");
  }
  {
    auto result = otf_propagate (ch_, "---", "x");
    assert (result.first == "###");
    assert (result.second == "#");
  }
  {
    auto result = otf_propagate (add_, "111?", "1??");
    assert (result.first == "1111");
    assert (result.second == "100");
  }
  {
    auto result = otf_propagate (xor_, "-x?", "-");
    assert (result.first == "-xx");
  }
#endif
}

void test_otf_2bit_eqs () {
#if !IS_LI2024
  {
    auto equations = otf_2bit_eqs (
        add_, "-0n10n", "5x-",
        {{1, 0, 0, 0, 0, 0, 0, 0, 2}, {3, 0, 0, 0, 0, 0, 0, 0, 4}},
        "+.......+");
    assert (equations.size () == 2);
    assert (equations[0].ids[0] == 1 && equations[0].ids[1] == 2);
    assert (equations[0].diff == 1);
    assert (equations[1].ids[0] == 3 && equations[1].ids[1] == 4);
    assert (equations[1].diff == 1);
  }
  {
    auto equations = otf_2bit_eqs (add_, "-1101-11", "110",
                                   {{1, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0},
                                    {3, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0}},
                                   "+....+.....");
    assert (equations.size () == 2);
    assert (equations[0].ids[0] == 1 && equations[0].ids[1] == 2);
    assert (equations[0].diff == 1);
    assert (equations[1].ids[0] == 3 && equations[1].ids[1] == 4);
    assert (equations[1].diff == 1);
  }
  {
    auto equations = otf_2bit_eqs (add_, "u0u01-10", "un-",
                                   {{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 2},
                                    {0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 4}},
                                   ".....+....+");
    assert (equations.size () == 2);
    assert (equations[0].ids[0] == 1 && equations[0].ids[1] == 2);
    assert (equations[0].diff == 0);
    assert (equations[1].ids[0] == 3 && equations[1].ids[1] == 4);
    assert (equations[1].diff == 0);
  }
  {
    auto equations = otf_2bit_eqs (xor_, "-0-", "0",
                                   {{1, 0, 2, 0}, {3, 0, 4, 0}}, "+.+.");
    assert (equations.size () == 2);
  }
  {
    auto equations = otf_2bit_eqs (
        add_, "xu110n-", "??u",
        {{1, 0, 0, 0, 0, 0, 2, 0, 0, 0}, {3, 0, 0, 0, 0, 0, 4, 0, 0, 0}},
        "+.....+...");
    assert (equations.size () == 2);
    assert (equations[0].ids[0] == 1);
    assert (equations[0].ids[1] == 2);
    assert (equations[0].diff == 0);
    assert (equations[1].ids[0] == 3);
    assert (equations[1].ids[1] == 4);
    assert (equations[1].diff == 1);
  }
#endif
}

void test_consistency_checker () {
  TwoBit two_bit;
  list<Equation *> equations;
  equations.push_back (new Equation{{1, 2}, 0});
  equations.push_back (new Equation{{2, 3}, 0});
  equations.push_back (new Equation{{3, 4}, 0});
  equations.push_back (new Equation{{1, 4}, 1});
  equations.push_back (new Equation{{100, 101}, 1});
  equations.push_back (new Equation{{101, 102}, 0});
  equations.push_back (new Equation{{102, 103}, 0});
  equations.push_back (new Equation{{100, 103}, 0});
  auto conflict_eqs = check_consistency (equations, true);
  assert (conflict_eqs.size () == 2);
  assert (conflict_eqs[0].ids[0] == 1 && conflict_eqs[0].ids[1] == 4 &&
          conflict_eqs[0].diff == 1);
  assert (conflict_eqs[1].ids[0] == 100 && conflict_eqs[1].ids[1] == 103 &&
          conflict_eqs[1].diff == 0);

  for (auto &equation : equations)
    delete equation;
}

void test_bit_manipulator () {
  uint32_t x = 5, y = 100;
  uint64_t z = to_uint64_t (x, y);

  uint32_t x_, y_;
  from_uint64_t (z, x_, y_);
  assert (x == x_ && y == y_);
}

void test_linear_prop () {
  NTL::mat_GF2 mat_A;
  mat_A.SetDims (16, 16);

  // Express the function as linear equations
  int x_map[4] = {0, 2, 4, 6};
  int y_map[4] = {8, 10, 12, 14};
  for (int i = 0; i < 4; i++) {
    int x_indices[3] = {(i + 1) % 4, (i + 2) % 4, (i + 3) % 4};

    // Block f
    for (int x = 0; x < 3; x++)
      mat_A[i * 2][x_map[x_indices[x]]] = 1;
    mat_A[i * 2][y_map[i]] = 1;

    // Block g
    for (int x = 0; x < 3; x++)
      mat_A[i * 2 + 1][x_map[x_indices[x]] + 1] = 1;
    mat_A[i * 2 + 1][y_map[i] + 1] = 1;
  }

  linear_propagate (mat_A, "???1", "00--");
}

void test_2_bit_graph () {
  vector<int> antecedent;
  {
    TwoBitGraph graph;
    graph.add_edge (15024, 15013, 1, &antecedent);
    graph.add_edge (15024, 15088, 1, &antecedent);
    graph.add_edge (15013, 15077, 1, &antecedent);
    graph.add_edge (15088, 15077, 0, &antecedent);
    graph.add_edge (15088, 15099, 0, &antecedent);
    graph.add_edge (15099, 15090, 1, &antecedent);
    graph.add_edge (15090, 15078, 1, &antecedent);
    graph.add_edge (15078, 15089, 0, &antecedent);
    graph.add_edge (15089, 15077, 1, &antecedent);
    graph.add_edge (15078, 15014, 1, &antecedent);
    graph.add_edge (15090, 15026, 0, &antecedent);

    {
      list<uint32_t> path =
          graph.shortest_inconsistent_cycle (15088, 15077);
      assert ((path == list<uint32_t>{15088, 15024, 15013, 15077}));
    }
    {
      list<uint32_t> path =
          graph.shortest_inconsistent_cycle (15024, 15013);
      assert ((path == list<uint32_t>{15024, 15088, 15077, 15013}));
    }
    {
      list<uint32_t> path =
          graph.shortest_inconsistent_cycle (15078, 15090);
      assert ((path ==
               list<uint32_t>{15078, 15089, 15077, 15088, 15099, 15090}));
    }
  }

  {
    TwoBitGraph graph;
    graph.add_edge (1773, 1901, 0, &antecedent);
    graph.add_edge (1901, 1965, 0, &antecedent);
    graph.add_edge (1965, 1956, 1, &antecedent);
    graph.add_edge (1956, 1979, 1, &antecedent);
    graph.add_edge (1979, 1915, 1, &antecedent);
    graph.add_edge (1915, 1892, 0, &antecedent);
    graph.add_edge (1892, 1912, 1, &antecedent);
    graph.add_edge (1912, 1901, 1, &antecedent);

    list<uint32_t> path = graph.shortest_inconsistent_cycle (1912, 1892);
    assert (
        (path == list<uint32_t>{1912, 1901, 1965, 1956, 1979, 1915, 1892}));
  }

  {
    TwoBitGraph graph;
    graph.add_edge (14895, 15023, 0, &antecedent);
    graph.add_edge (15023, 15087, 0, &antecedent);
    graph.add_edge (15087, 15096, 1, &antecedent);
    graph.add_edge (15096, 15032, 0, &antecedent);
    graph.add_edge (15032, 14904, 0, &antecedent);
    graph.add_edge (14904, 14895, 0, &antecedent);
    graph.add_edge (15032, 15023, 1, &antecedent);

    {
      list<uint32_t> path =
          graph.shortest_inconsistent_cycle (15032, 15023);
      assert ((path == list<uint32_t>{15032, 14904, 14895, 15023}));
    }
  }

  {
    TwoBitGraph graph;
    vector<int> antecedent1 = {1955, 15075, 27598, 27607, 8385, 21505};
    vector<int> antecedent2 = {27598, 27502, -27406, 34033};
    vector<int> antecedent3 = {-1891, -15011, 27502, 27511, 8065, 21185};
    vector<int> antecedent4 = {27607, 27511, 1847, -14967, 34042};
    vector<int> antecedent5 = {27598, 27502, 1838, -14958, 34033};
    graph.add_edge (15022, 15086, 0, &antecedent2);
    graph.add_edge (15022, 15086, 0, &antecedent5);
    graph.add_edge (15022, 15031, 1, &antecedent3);
    graph.add_edge (15086, 15095, 0, &antecedent1);
    graph.add_edge (15095, 15031, 0, &antecedent4);

    {
      vector<vector<int> *> blocking_antecedents;
      list<uint32_t> path = graph.shortest_inconsistent_cycle (
          15095, 15031, &blocking_antecedents);
      assert ((path == list<uint32_t>{15095, 15086, 15022, 15031}));
      assert ((blocking_antecedents ==
               vector<vector<int> *>{&antecedent4, &antecedent3,
                                     &antecedent2, &antecedent1}));
    }
  }

  {
    TwoBitGraph graph;
    vector<int> antecedent1 = {};
    vector<int> antecedent2 = {};
    vector<int> antecedent3 = {};
    vector<int> antecedent4 = {};
    vector<int> antecedent5 = {};
    vector<int> antecedent6 = {};
    graph.add_edge (1892, 1956, 1, &antecedent1);
    graph.add_edge (1892, 1912, 0, &antecedent2);
    graph.add_edge (1912, 1976, 0, &antecedent3);
    graph.add_edge (1976, 1956, 1, &antecedent4);
    graph.add_edge (1976, 1965, 1, &antecedent5);
    graph.add_edge (1956, 1965, 0, &antecedent6);

    auto path = graph.shortest_inconsistent_cycle (1892, 1956);
    assert (path.empty ());
  }

  {
    TwoBitGraph graph;
    vector<int> antecedent1 = {};
    vector<int> antecedent2 = {};
    vector<int> antecedent3 = {};
    vector<int> antecedent4 = {};
    vector<int> antecedent5 = {};
    vector<int> antecedent6 = {};
    graph.add_edge (1, 2, 0, &antecedent1);
    graph.add_edge (1, 2, 0, &antecedent1);
    graph.add_edge (1, 2, 0, &antecedent2);

    assert (graph.get_antecedents (1, 2).size () == 2);

    graph.remove_edge (1, 2, 0, &antecedent1);
    assert (graph.get_antecedents (1, 2).size () == 1);
    graph.remove_edge (1, 2, 0, &antecedent1);
    assert (graph.get_antecedents (1, 2).size () == 1);

    graph.remove_edge (1, 2, 0, &antecedent3);
    assert (graph.get_antecedents (1, 2).size () == 1);

    graph.remove_edge (1, 2, 1, &antecedent2);
    assert (graph.get_antecedents (1, 2).size () == 1);

    graph.remove_edge (1, 2, 0, &antecedent2);
    assert (graph.get_antecedents (1, 2).size () == 0);
  }
}

void run_tests () {
  printf ("Running tests\n");
  test_group_wordwise_prop ();
  test_rotate_word ();
  test_otf_propagate ();
  test_otf_2bit_eqs ();
  test_consistency_checker ();
  test_bit_manipulator ();
  // test_linear_prop ();
  test_2_bit_graph ();
  printf ("All tests passed!\n");
}
} // namespace SHA256
