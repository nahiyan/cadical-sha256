#include "sha256_tests.hpp"
#include "sha256.hpp"
#include "sha256_propagate.hpp"
#include "sha256_util.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>

namespace SHA256 {
void test_int_diff () {
  assert (_int_diff ("0n0n001001u-1u1n01un010n01n00110") == 2955087584);
  assert (_int_diff ("nnnnn-nnnn--------nuu-----------") == 71301120);
  assert (_int_diff ("nnnnn-nnnA--------nuu-----------") == -1);
  assert (_int_diff ("--------------------------------") == 0);
  assert (_int_diff ("0n0n001001u") == 1409);
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
}

void test_gen_vars () {
  vector<string> expected = {
      "",  "vv1", "vv", "",   "v1", "vv", "v", "",   "1",
      "v", "v",   "v",  "vv", "vv", "vv", "v", "vv", "",
  };
  auto actual = gen_vars ({"-uxxu-xx1u---x-00x", "--?0-?0--u?A-???5-"});
  assert (actual == expected);
}

void test_brute_force () {
  assert (brute_force ({"vv", "v"}, 2) == "vvv");
  assert (brute_force ({"vv", "v"}, 4) == "111");
  assert (brute_force ({"vv", "vv"}, 0, 3) == "vvvv");
  assert (brute_force ({"vv", "vv", "v1"}, 8) == "vvvvv");
}

void test_apply_grounding () {
  // TODO: Add tests
}
void test_derive_words () {
  {
    vector<string> expected = {"--uunu-nx--x", "--u--n-B-BB-"};
    auto actual = derive_words ({"--xxxx-xx--x", "--B--D-BBBB-"}, 1147);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"-u-------uu-uu-u0u1--u-0-n---n0-"};
    auto actual =
        derive_words ({"-u-?-----uu-uu-u0u1?-u-0-n?--n0-"}, 1080902588);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"---nuu1ununnn-1unnnnnn-n--0-1---"};
    auto actual =
        derive_words ({"---nuu1ununnn-1uxnxnxn-x--0-1---"}, 4236772096);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"x-n-nn-xxn-u-u--uuuux-u---x-x---",
                               "-------B-n--u------D---n--BBu---"};
    auto actual = derive_words ({"x-x-xx-xxn-x-x--xxxxx-x---x-x---",
                                 "-------BDD--B------D---DD-BBBB--"},
                                1411180832);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"xxxxxxu----n-unnnu-x--uxxxu-xxx-",
                               "DDDDD-n-nn--u-----D-u--DD-BBBB--"};
    auto actual = derive_words ({"xxxxxxx----x-xxxxx-x--uxxxx-xxx-",
                                 "DDDDD-D-nn--B-----D-B--DD-BBBB--"},
                                725137662);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"----x-nx---n--n--nu--uunu-nx--x-",
                               "DDDD-nD-nn--u-----n--u--n-B-BB--"};
    auto actual = derive_words ({"----x-xx---x--x--xx--xxxx-xx--x-",
                                 "DDDD-DD-nn-Du-----D--B--D-BBBB--"},
                                2151008502);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"--n-1u-----00--x1-n-x--n--------",
                               "un000unuuu110A5-11n-x0nn110-0nu1"};
    auto actual = derive_words ({"--n-1x-----00--x1-n-x--n--------",
                                 "un000unuuu110A5-11n-x0nn110-0nu1"},
                                666942462);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"0nun1n--uu--n--nuuu0u--uu-uuuu0-"};
    auto actual =
        derive_words ({"0nun1x--ux--n--nxxu0x--ux-uuxu0-"}, 3434604988);
    assert (expected == actual);
  }

  {
    vector<string> expected = {"xu-nnu--uxxu-xn1u---x-00x-u0-1--",
                               "---------?0-?0--u-u-??n5-u------"};
    auto actual = derive_words ({"xx-nnx--uxxu-xx1u---x-00x-u0-1--",
                                 "---------?0-?0--u?A-???5-u---?--"},
                                2896892384);
    assert (expected == actual);
  }
}

void test_rotate_word () {
  assert ("u10u101u0-0u1-nn-n-u-1u---11un0u" ==
          rotate_word ("0u1-nn-n-u-1u---11un0uu10u101u0-", -10));
  assert ("u0-0u1-nn-n-u-1u---11un0uu10u101" ==
          rotate_word ("0u1-nn-n-u-1u---11un0uu10u101u0-", -3));
  assert ("0000u1-nn-n-u-1u---11un0uu10u101" ==
          rotate_word ("0u1-nn-n-u-1u---11un0uu10u101u0-", -3, false));
}

void test_otf_add_propagate () {
  {
    auto result = otf_add_propagate ("u?u-n?u", "???");
    assert (result.second == "B??" && result.first == "u?u-n?u");
  }
  {
    auto result = otf_add_propagate ("????", "1??");
    assert (result.second == "100" && result.first == "1111");
  }
  {
    auto result = otf_add_propagate ("n?0", "?u");
    assert (result.second == "nu" && result.first == "n10");
  }
}

void run_tests () {
  printf ("Running tests\n");
  test_int_diff ();
  test_adjust_constant ();
  test_is_congruent ();
  test_can_overflow ();
  test_gen_vars ();
  test_brute_force ();
  test_apply_grounding ();
  test_derive_words ();
  test_rotate_word ();
  test_otf_add_propagate ();
  printf ("All tests passed!\n");
}
} // namespace SHA256
