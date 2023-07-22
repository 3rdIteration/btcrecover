#!/usr/bin/env python
# -*- coding: utf-8 -*-

# test_passwords.py -- unit tests for btcrecover.py
# Copyright (C) 2014-2017 Christopher Gurnee
#               2019-2021 Stephen Rothery
#
# This file is part of btcrecover.
#
# btcrecover is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# btcrecover is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/


import warnings, os, unittest, pickle, tempfile, shutil, multiprocessing, time, gc, filecmp, sys, hashlib
if __name__ == '__main__':
    sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))

from btcrecover import btcrpass

import btcrecover.opencl_helpers

class NonClosingBase(object):
    pass


tstr = str
def setUpModule():
    global orig_warnings, tstr, tchr, utf8_opt, BytesIO, StringIO, BytesIONonClosing, StringIONonClosing

    # orig_warnings = warnings.catch_warnings()
    # orig_warnings.__enter__()  # save the current warnings settings (it's a context manager)
    # # Convert warnings to errors:
    # warnings.simplefilter("error")
    # # Ignore import warnigns that appear in Python 3.6
    # warnings.filterwarnings("ignore", message=r"Not importing directory .*: missing __init__", category=ImportWarning)
    # # Ignore protobuf deprecation warnings that appear in Python 3.6 and 3.7
    # warnings.filterwarnings("ignore", message="Using or importing the ABCs from 'collections' instead of from 'collections.abc' is deprecated, and in 3.8 it will stop working", category=DeprecationWarning)

    import io
    BytesIO  = io.BytesIO
    StringIO = io.StringIO
    class BytesIONonClosing(BytesIO, NonClosingBase):
        def close(self): pass
    class StringIONonClosing(StringIO, NonClosingBase):
        def close(self): pass
    btcrpass.enable_unicode_mode()
    tchr = chr
    utf8_opt = " --utf8"
    print("** Testing in Unicode character mode **")


def tearDownModule():
    global tstr
    tstr = None
    # orig_warnings.__exit__(None, None, None)  # restore the original warnings settings


WALLET_DIR = os.path.join(os.path.dirname(__file__), "test-wallets")
TYPOS_DIR  = os.path.join(os.path.dirname(__file__), "..", "..", "typos")


# Similar to unittest.skipUnless, except the first arg is a function returning a bool instead
# of just a bool. This function isn't called until just before the test is to be run. This
# permits checking the character mode (which isn't set until later) and prevents multiprocessing
# under Windows from calling skipUnless which would otherwise produce spurious warning messages.
def skipUnless(condition_func, reason):
    assert callable(condition_func)
    def decorator(test_func):
        def skip_or_test(self):
            if not condition_func():
                self.skipTest(reason)
            test_func(self)
        return skip_or_test
    return decorator


class GeneratorTester(unittest.TestCase):

    # tokenlist == a list of lines (w/o "\n") which will become the tokenlist file
    # expected_passwords == a list of passwords which should be produced from the tokenlist
    # extra_cmd_line == a single string of additional command-line options
    # test_passwordlist == whether or not to also test --passwordlist
    # chunksize == the password generator chunksize
    # expected_skipped == the expected # of skipped passwords, if any
    # extra_kwds == additional StringIO objects to act as file stand-ins
    def do_generator_test(self, tokenlist, expected_passwords, extra_cmd_line = None, test_passwordlist = False,
                          chunksize = sys.maxsize, expected_skipped = None, **extra_kwds):
        assert isinstance(tokenlist, list)
        assert isinstance(expected_passwords, list)
        tokenlist_str = tstr("\n".join(tokenlist))
        args = tstr("__funccall --listpass" + utf8_opt).split()
        if extra_cmd_line:
            args += tstr(extra_cmd_line).split(tstr(" "))

        btcrpass.parse_arguments([tstr("--tokenlist")] + args, tokenlist=StringIO(tokenlist_str), disable_security_warning_param = True, **extra_kwds)
        tok_it, skipped = btcrpass.password_generator_factory(chunksize)
        if expected_skipped is not None:
            self.assertEqual(skipped, expected_skipped)
        try:
            generated_passwords = tok_it.__next__()
            for p in generated_passwords:
                self.assertIs(type(p), tstr)
            self.assertEqual(generated_passwords, expected_passwords)
        except StopIteration:
            self.assertEqual([], expected_passwords)
        if not test_passwordlist: return tok_it,

        # Reset any files passed in as extra parameters
        for sio in filter(lambda s: isinstance(s, NonClosingBase), extra_kwds.values()):
            sio.seek(0)

        btcrpass.parse_arguments([tstr("--passwordlist")] + args, passwordlist=StringIO(tokenlist_str), disable_security_warning_param = True, **extra_kwds)
        pwl_it, skipped = btcrpass.password_generator_factory(chunksize)
        if expected_skipped is not None:
            self.assertEqual(skipped, expected_skipped)
        try:
            generated_passwords = pwl_it.__next__()
            for p in generated_passwords:
                self.assertIs(type(p), tstr)
            self.assertEqual(generated_passwords, expected_passwords)
        except StopIteration:
            self.assertEqual([], expected_passwords)
        return tok_it, pwl_it

    # tokenlist == a list of lines (w/o "\n") which will become the tokenlist file
    # expected_error == a (partial) error message that should be produced from the tokenlist
    # extra_cmd_line == a single string of additional command-line options
    # extra_kwds == additional StringIO objects to act as file stand-ins
    def expect_syntax_failure(self, tokenlist, expected_error, extra_cmd_line = "", **extra_kwds):
        assert isinstance(tokenlist, list)
        with self.assertRaises(SystemExit) as cm:
            btcrpass.parse_arguments(
                (tstr("--tokenlist __funccall --listpass "+extra_cmd_line+utf8_opt)).split(),
                tokenlist = StringIO(tstr("\n".join(tokenlist))), disable_security_warning_param = True,
                **extra_kwds)
        self.assertIn(expected_error, cm.exception.code)


class Test01Basics(GeneratorTester):

    def test_alternate(self):
        self.do_generator_test(["one", "two"], ["one", "two", "twoone", "onetwo"])
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_alternate_unicode(self):
        self.do_generator_test(["один", "два"], ["один", "два", "дваодин", "одиндва"])

    def test_mutex(self):
        self.do_generator_test(["one two three"], ["one", "two", "three"])

    def test_require(self):
        self.do_generator_test(["one", "+ two", "+ three"],
            ["threetwo", "twothree", "threetwoone", "threeonetwo",
            "twothreeone", "twoonethree", "onethreetwo", "onetwothree"])

    def test_chunksize_divisible(self):
        tok_it, = self.do_generator_test(["one two three four five six"], ["one", "two", "three"], "", False, 3)
        self.assertEqual(tok_it.__next__(), ["four", "five", "six"])
        self.assertRaises(StopIteration, tok_it.__next__)
    def test_chunksize_indivisible(self):
        tok_it, = self.do_generator_test(["one two three four five"], ["one", "two", "three"], "", False, 3)
        self.assertEqual(tok_it.__next__(), ["four", "five"])
        self.assertRaises(StopIteration, tok_it.__next__)
    def test_chunksize_modified(self):
        tok_it, = self.do_generator_test(["one two three four five six"], ["one", "two"], "", False, 2)
        self.assertIsNone(tok_it.send( (3, False) ))
        self.assertEqual(tok_it.__next__(), ["three", "four", "five"])
        self.assertEqual(tok_it.__next__(), ["six"])
        self.assertRaises(StopIteration, tok_it.__next__)

    def test_only_yield_count(self):
        btcrpass.parse_arguments(("--tokenlist __funccall --listpass"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("one two three four five six")), disable_security_warning_param = True)
        tok_it = btcrpass.password_generator(2, only_yield_count=True)
        self.assertEqual(tok_it.__next__(), 2)
        self.assertIsNone(tok_it.send( (3, True) ))
        self.assertEqual(tok_it.__next__(), 3)
        self.assertIsNone(tok_it.send( (3, False) ))
        self.assertEqual(tok_it.__next__(), ["six"])
        self.assertRaises(StopIteration, tok_it.__next__)

        btcrpass.parse_arguments(("--passwordlist __funccall --listpass"+utf8_opt).split(),
                                 passwordlist = StringIO(tstr("one two three four five six".replace(" ", "\n"))), disable_security_warning_param = True)
        pwl_it = btcrpass.password_generator(2, only_yield_count=True)
        self.assertEqual(pwl_it.__next__(), 2)
        self.assertIsNone(pwl_it.send( (3, True) ))
        self.assertEqual(pwl_it.__next__(), 3)
        self.assertIsNone(pwl_it.send( (3, False) ))
        self.assertEqual(pwl_it.__next__(), ["six"])
        self.assertRaises(StopIteration, pwl_it.__next__)

    def test_only_yield_count_all(self):
        btcrpass.parse_arguments(("--tokenlist __funccall --listpass"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("one two three")), disable_security_warning_param = True)
        tok_it = btcrpass.password_generator(4, only_yield_count=True)
        self.assertEqual(tok_it.__next__(), 3)
        self.assertRaises(StopIteration, tok_it.__next__)

        btcrpass.parse_arguments(("--passwordlist __funccall --listpass"+utf8_opt).split(),
                                 passwordlist = StringIO(tstr("one two three".replace(" ", "\n"))), disable_security_warning_param = True)
        pwl_it = btcrpass.password_generator(4, only_yield_count=True)
        self.assertEqual(pwl_it.__next__(), 3)
        self.assertRaises(StopIteration, pwl_it.__next__)

    def test_count(self):
        btcrpass.parse_arguments(("--tokenlist __funccall --listpass"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("one two three")), disable_security_warning_param = True)
        self.assertEqual(btcrpass.count_and_check_eta(1.0), 3)
    def test_count_zero(self):
        btcrpass.parse_arguments(("--tokenlist __funccall --listpass"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("")), disable_security_warning_param = True)
        self.assertEqual(btcrpass.count_and_check_eta(1.0), 0)
    # the size of a "chunk" is == btcrpass.PASSWORDS_BETWEEN_UPDATES == 100000
    def test_count_one_chunk(self):
        assert btcrpass.PASSWORDS_BETWEEN_UPDATES == 100000
        btcrpass.parse_arguments(("--tokenlist __funccall --listpass"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("%5d")), disable_security_warning_param = True)
        self.assertEqual(btcrpass.count_and_check_eta(1.0), 100000)
    def test_count_two_chunks(self):
        assert btcrpass.PASSWORDS_BETWEEN_UPDATES == 100000
        btcrpass.parse_arguments(("--tokenlist __funccall --listpass"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("%5d 100000")), disable_security_warning_param = True)
        self.assertEqual(btcrpass.count_and_check_eta(1.0), 100001)

    def test_token_counts_min_0(self):
        self.do_generator_test(["one"], ["", "one"], "--min-tokens 0")
    def test_token_counts_min_2(self):
        self.do_generator_test(["one", "two", "three"],
            ["twoone", "onetwo", "threeone", "onethree", "threetwo", "twothree", "threetwoone",
            "threeonetwo", "twothreeone", "twoonethree", "onethreetwo", "onetwothree"],
            "--min-tokens 2")
    def test_token_counts_max_2(self):
        self.do_generator_test(["one", "two", "three"],
            ["one", "two", "twoone", "onetwo", "three", "threeone", "onethree", "threetwo", "twothree"],
            "--max-tokens 2")
    def test_token_counts_min_max_2(self):
        self.do_generator_test(["one", "two", "three"],
            ["twoone", "onetwo", "threeone", "onethree", "threetwo", "twothree"],
            "--min-tokens 2 --max-tokens 2")

    def test_truncate(self):
        self.do_generator_test(["one", "two", "three"],
            ["o", "t"],
            "--truncate-length 1")

    def test_password_repeats_postypos(self):
        self.do_generator_test(["aa"],
            ["aa", "aaaa", "Xa", "XaXa", "aX", "aXaX"],
            "--password-repeats-posttypos --typos-replace X")

    def test_password_repeats_pretypos(self):
        self.do_generator_test(["aa"],
            ["aa", "Xa", "aX", "aaaa", "Xaaa", "aXaa", "aaXa", "aaaX"],
            "--password-repeats-pretypos --typos-replace X")

    def test_password_repeats_x3(self):
        self.do_generator_test(["one"],
            ["one", "oneone", "oneoneone"],
            "--password-repeats-posttypos --max-password-repeats 3")

    def test_empty_file(self):
        self.do_generator_test([], [], test_passwordlist=True)
    def test_one_char_file(self):
        self.do_generator_test(["a"], ["a"], test_passwordlist=True)
    def test_comments(self):
        self.do_generator_test(["#one", " #two", "#three"], ["#two"])

    def test_z_all(self):
        self.do_generator_test(["1", "2 3", "+ 4 5"], list(map(str, [
            4,41,14,42,24,421,412,241,214,142,124,43,34,431,413,341,314,143,134,
            5,51,15,52,25,521,512,251,215,152,125,53,35,531,513,351,315,153,135])))


class Test02Anchors(GeneratorTester):

    def test_begin(self):
        self.do_generator_test(["^one", "^two", "three"],
            ["one", "two", "three", "onethree", "twothree"])
    def test_begin_0len(self):
        self.do_generator_test(["^"], [""])

    def test_end(self):
        self.do_generator_test(["one$", "two$", "three"],
            ["one", "two", "three", "threeone", "threetwo"])
    def test_end_0len(self):
        self.do_generator_test(["$"], [""])

    def test_begin_and_end(self):
        self.expect_syntax_failure(["^one$"], "token on line 1 is anchored with both ^ at the beginning and $ at the end")

    def test_positional(self):
        self.do_generator_test(["one", "^2^two", "^3^three"], ["one", "onetwo", "onetwothree"])
    def test_positional_old(self):
        self.do_generator_test(["one", "^2$two", "^3$three"], ["one", "onetwo", "onetwothree"])
    def test_positional_0len(self):
        self.do_generator_test(["+ ^1^", "^2^two"], ["", "two"])

    def test_positional_invalid(self):
        self.expect_syntax_failure(["^0^zero"], "anchor position of token on line 1 must be 1 or greater")

    def test_middle(self):
        self.do_generator_test(["^one", "^2,2^two", "^,3^three", "^,^four", "five$"],
            ["one", "five", "onefive", "onetwofive", "onethreefive", "onetwothreefive", "onefourfive",
            "onetwofourfive", "onefourthreefive", "onethreefourfive", "onetwothreefourfive"])
    def test_middle_old(self):
        self.do_generator_test(["^one", "^2,2$two", "^,3$three", "^,$four", "five$"],
            ["one", "five", "onefive", "onetwofive", "onethreefive", "onetwothreefive", "onefourfive",
            "onetwofourfive", "onefourthreefive", "onethreefourfive", "onetwothreefourfive"])
    def test_middle_0len(self):
        self.do_generator_test(["one", "+ ^,^", "^3^three"], ["onethree"])

    def test_middle_invalid_begin(self):
        self.expect_syntax_failure(["^1,^one"],  "anchor range of token on line 1 must begin with 2 or greater")
    def test_middle_invalid_range(self):
        self.expect_syntax_failure(["^3,2^one"], "anchor range of token on line 1 is invalid")
    def test_not_middle(self):
        self.do_generator_test(["^2,3one"], ["2,3one"])

    # test for the bug fixed in v0.11.1
    def test_tokens_duplicate(self):
        self.do_generator_test(["one", "one", "^,$two"], ["one", "oneone", "onetwoone"], "-d")

    def test_relative_one(self):
        self.do_generator_test(["^r0^one", "two"], ["one", "two", "twoone", "onetwo"])

    def test_relative_two(self):
        self.do_generator_test(["^r0^one", "^r1^two"], ["one", "two", "onetwo"])

    def test_relative_same(self):
        self.do_generator_test(["^r1^one", "^r1^two"], ["one", "two", "twoone", "onetwo"])


LEET_MAP_FILE = os.path.join(TYPOS_DIR, "leet-map.txt")
class Test03WildCards(GeneratorTester):

    def test_basics_1(self):
        self.do_generator_test(["%d"], list(map(tstr, range(10))), "--has-wildcards", True)
    def test_basics_2(self):
        self.do_generator_test(["%dtest"], [str(i)+"test" for i in range(10)], "--has-wildcards", True)
    def test_basics_3(self):
        self.do_generator_test(["te%dst"], ["te"+str(i)+"st" for i in range(10)], "--has-wildcards", True)
    def test_basics_4(self):
        self.do_generator_test(["test%d"], ["test"+str(i) for i in range(10)], "--has-wildcards", True)

    def test_invalid_nocust(self):
        self.expect_syntax_failure(["%c"],    "invalid wildcard")
    def test_invalid_nocust_cap(self):
        self.expect_syntax_failure(["%C"],    "invalid wildcard")
    def test_invalid_notype(self):
        self.expect_syntax_failure(["test%"], "invalid wildcard")

    def test_multiple(self):
        self.do_generator_test(["%d%d"], ["{:02}".format(i) for i in range(100)], "--has-wildcards", True)

    def test_length_2(self):
        self.do_generator_test(["%2d"],  ["{:02}".format(i) for i in range(100)], "--has-wildcards", True)
    def test_length_range(self):
        self.do_generator_test(["%0,2d"],
            [""] +
            list(map(tstr, range(10))) +
            ["{:02}".format(i) for i in range(100)],
            "--has-wildcards", True)

    def test_length_invalid_range(self):
        self.expect_syntax_failure(["%2,1d"], "on line 1: max wildcard length (1) must be >= min length (2)")
    def test_invalid_length_1(self):
        self.expect_syntax_failure(["%2,d"],  "invalid wildcard")
    def test_invalid_length_2(self):
        self.expect_syntax_failure(["%,2d"],  "invalid wildcard")

    def test_case_lower(self):
        self.do_generator_test(["%a"], list(map(tchr, range(ord("a"), ord("z")+1))), "--has-wildcards", True)
    def test_case_upper(self):
        self.do_generator_test(["%A"], list(map(tchr, range(ord("A"), ord("Z")+1))), "--has-wildcards", True)
    def test_case_insensitive_1(self):
        self.do_generator_test(["%ia"],
            list(map(tchr, range(ord("a"), ord("z")+1))) + list(map(tchr, range(ord("A"), ord("Z")+1))), "--has-wildcards", True)
    def test_case_insensitive_2(self):
        self.do_generator_test(["%iA"],
            list(map(tchr, range(ord("A"), ord("Z")+1))) + list(map(tchr, range(ord("a"), ord("z")+1))), "--has-wildcards", True)

    def test_custom(self):
        self.do_generator_test(["%c"],  ["a", "b", "c", "D", "2"], "--has-wildcards --custom-wild a-cD2", True)
    def test_custom_upper(self):
        self.do_generator_test(["%C"],  ["A", "B", "C", "D", "2"], "--has-wildcards --custom-wild a-cD2", True)
    def test_custom_insensitive_1(self):
        self.do_generator_test(["%ic"], ["a", "b", "c", "D", "2", "A", "B", "C", "d"],
            "--has-wildcards --custom-wild a-cD2 -d", True)
    def test_custom_insensitive_2(self):
        self.do_generator_test(["%iC"], ["A", "B", "C", "d", "2", "a", "b", "c", "D"],
            "--has-wildcards --custom-wild a-cD2 -d", True)

    def test_set(self):
        self.do_generator_test(["%[abcc-]"], ["a", "b", "c", "-"], "--has-wildcards -d", True)
    def test_set_insensitive(self):
        self.do_generator_test(["%i[abcc-]"], ["a", "b", "c", "-", "A", "B", "C"], "--has-wildcards -d", True)
    def test_set_withspace(self):
        self.do_generator_test(["%[a b]"], ["a", " ", "b"], "--has-wildcards -d", True)
    def test_noset(self):
        self.do_generator_test(["%%[not-a-range]"], ["%[not-a-range]"], "--has-wildcards", True)

    def test_range_1(self):
        self.do_generator_test(["%[1dc-f]"],  ["1", "d", "c", "e", "f"], "--has-wildcards -d", True)
    def test_range_2(self):
        self.do_generator_test(["%[a-c-e]"], ["a", "b", "c", "-", "e"], "--has-wildcards", True)
    def test_range_insensitive(self):
        self.do_generator_test(["%i[1dc-f]"], ["1", "d", "c", "e", "f", "D", "C", "E", "F"], "--has-wildcards -d", True)

    def test_range_invalid(self):
        self.expect_syntax_failure(["%[c-a]"],  "first character in wildcard range 'c' > last 'a'")

    def test_contracting_1(self):
        self.do_generator_test(["a%0,2-bcd"], ["abcd", "bcd", "acd", "cd", "ad"], "--has-wildcards -d", True)
    def test_contracting_2(self):
        self.do_generator_test(["abcd%1,2-"], ["abc", "ab"], "--has-wildcards -d", True)
    def test_contracting_right(self):
        self.do_generator_test(["ab%0,1>cd"], ["abcd", "abd"], "--has-wildcards -d", True)
    def test_contracting_left(self):
        self.do_generator_test(["ab%0,3<cd"], ["abcd", "acd", "cd"], "--has-wildcards -d", True)
    def test_contracting_multiple(self):
        self.do_generator_test(["%0,3-ab%[X]cd%0,3-"],
            ["abXcd", "abXc", "abX", "bXcd", "bXc", "bX", "Xcd", "Xc", "X"], "--has-wildcards -d", True)

    def test_backreference(self):
        self.do_generator_test(["%[ab]%b"], ["aa", "bb"], "--has-wildcards -d", True)
    def test_backreference_length(self):
        self.do_generator_test(["%[ab]%2,3b"], ["aaa", "aaaa", "bbb", "bbbb"], "--has-wildcards -d", True)
    def test_backreference_pos(self):
        self.do_generator_test(["%[ab]X%;2b"], ["aXa", "bXb"], "--has-wildcards -d", True)
    def test_backreference_pos_length(self):
        self.do_generator_test(["%[ab]X%2,3;2b"], ["aXaX", "aXaXa", "bXbX", "bXbXb"], "--has-wildcards -d", True)
    def test_backreference_bounds(self):
        self.do_generator_test(["%[ab]%1,3;3b"], ["a", "aa", "b", "bb"], "--has-wildcards -d", True)

    # Use a --delimiter of TAB below in case the LEET_MAP_FILE path contains any spaces
    @unittest.skipUnless(os.path.isfile(LEET_MAP_FILE), "requires leet-map.txt file")
    def test_backreference_map(self):
        self.do_generator_test(["%[bc]%;"+LEET_MAP_FILE+";b"],
            ["b8", "b6", "c("], "--has-wildcards -d --delimiter \t", True)
    @unittest.skipUnless(os.path.isfile(LEET_MAP_FILE), "requires leet-map.txt file")
    def test_backreference_map_missing(self):
        self.do_generator_test(["%[cd]%;"+LEET_MAP_FILE+";b"],
            ["c(", "dd"], "--has-wildcards -d --delimiter \t", True)
    @unittest.skipUnless(os.path.isfile(LEET_MAP_FILE), "requires leet-map.txt file")
    def test_backreference_map_length(self):
        self.do_generator_test(["%[bc]%2,3;"+LEET_MAP_FILE+";b"],
            ["b88", "b888", "b66", "b666", "c((", "c((("], "--has-wildcards -d --delimiter \t", True)
    @unittest.skipUnless(os.path.isfile(LEET_MAP_FILE), "requires leet-map.txt file")
    def test_backreference_map_pos(self):
        self.do_generator_test(["%[bc]X%;"+LEET_MAP_FILE+";2b"],
            ["bX8", "bX6", "cX("], "--has-wildcards -d --delimiter \t", True)
    @unittest.skipUnless(os.path.isfile(LEET_MAP_FILE), "requires leet-map.txt file")
    def test_backreference_map_pos_length(self):
        self.do_generator_test(["%[bc]X%2,3;"+LEET_MAP_FILE+";2b"],
            ["bX8%", "bX8%8", "bX6%", "bX6%6", "cX(%", "cX(%("], "--has-wildcards -d --delimiter \t", True)
    @unittest.skipUnless(os.path.isfile(LEET_MAP_FILE), "requires leet-map.txt file")
    def test_backreference_map_bounds(self):
        self.do_generator_test(["%[bc]%1,3;"+LEET_MAP_FILE+";3b"],
            ["b", "b8", "b6", "c", "c("], "--has-wildcards -d --delimiter \t", True)


class Test04Typos(GeneratorTester):

    def test_capslock(self):
        self.do_generator_test(["One2Three"], ["One2Three", "oNE2tHREE"],
            "--typos-capslock --typos 2 -d", True)
    def test_capslock_nocaps(self):
        self.do_generator_test(["123"], ["123"],
            "--typos-capslock --typos 2 -d", True)
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_capslock_unicode(self):
        self.do_generator_test(["Один2Три"], ["Один2Три", "оДИН2тРИ"],
            "--typos-capslock --typos 2 -d", True)
    def test_capslock_min_1(self):
        self.do_generator_test(["One2Three"], ["oNE2tHREE"],
            "--typos-capslock --typos 2 -d --min-typos 1", True)
    def test_capslock_min_2(self):
        self.do_generator_test(["One2Three"], [],
            "--typos-capslock --typos 2 -d --min-typos 2", True)

    def test_swap(self):
        self.do_generator_test(["abcdd"], ["abcdd", "bacdd", "acbdd", "abdcd", "badcd"],
            "--typos-swap --typos 2 -d", True)
    def test_swap_max(self):
        self.do_generator_test(["abcdd"], ["abcdd", "bacdd", "acbdd", "abdcd"],
            "--typos-swap --max-typos-swap 1 --typos 2 -d", True)
    def test_swap_min_1(self):
        self.do_generator_test(["abcdd"], ["bacdd", "acbdd", "abdcd", "badcd"],
            "--typos-swap --typos 2 -d --min-typos 1", True)
    def test_swap_min_2(self):
        self.do_generator_test(["abcdd"], ["badcd"],
            "--typos-swap --typos 2 -d --min-typos 2", True)
    def test_swap_min_3(self):
        self.do_generator_test(["abcdd"], [],
            "--typos-swap --typos 3 -d --min-typos 3", True)

    def test_repeat(self):
        self.do_generator_test(["abc"], ["abc", "aabc", "abbc", "abcc", "aabbc", "aabcc", "abbcc"],
            "--typos-repeat --typos 2 -d", True)
    def test_repeat_max(self):
        self.do_generator_test(["abc"], ["abc", "aabc", "abbc", "abcc"],
            "--typos-repeat --max-typos-repeat 1 --typos 2 -d", True)
    def test_repeat_min_1(self):
        self.do_generator_test(["abc"], ["aabc", "abbc", "abcc", "aabbc", "aabcc", "abbcc"],
            "--typos-repeat --typos 2 -d --min-typos 1", True)
    def test_repeat_min_2(self):
        self.do_generator_test(["abc"], ["aabbc", "aabcc", "abbcc"],
            "--typos-repeat --typos 2 -d --min-typos 2", True)
    def test_repeat_min_4(self):
        self.do_generator_test(["abc"], [],
            "--typos-repeat --typos 4 -d --min-typos 4", True)

    def test_delete(self):
        self.do_generator_test(["abc"], ["abc", "bc", "ac", "ab", "c", "b", "a"],
            "--typos-delete --typos 2 -d", True)
    def test_delete_max(self):
        self.do_generator_test(["abc"], ["abc", "bc", "ac", "ab"],
            "--typos-delete --max-typos-delete 1 --typos 2 -d", True)

    def test_case(self):
        self.do_generator_test(["abC1"], ["abC1", "AbC1", "aBC1", "abc1", "ABC1", "Abc1", "aBc1"],
            "--typos-case --typos 2 -d", True)
    def test_case_max(self):
        self.do_generator_test(["abC1"], ["abC1", "AbC1", "aBC1", "abc1"],
            "--typos-case --max-typos-case 1 --typos 2 -d", True)

    def test_closecase(self):
        self.do_generator_test(["one2Three"],
            ["one2Three", "One2Three", "one2three", "one2THree", "one2ThreE", "One2three",
            "One2THree", "One2ThreE", "one2tHree", "one2threE", "one2THreE"],
            "--typos-closecase --typos 2 -d", True)
    def test_closecase_max(self):
        self.do_generator_test(["one2Three"],
            ["one2Three", "One2Three", "one2three", "one2THree", "one2ThreE"],
            "--typos-closecase --max-typos-closecase 1 --typos 2 -d", True)

    def test_insert(self):
        self.do_generator_test(["abc"],
            ["abc", "Xabc", "aXbc", "abXc", "abcX", "XaXbc", "XabXc", "XabcX", "aXbXc", "aXbcX", "abXcX"],
            "--typos-insert X --typos 2 -d", True)
    def test_insert_max(self):
        self.do_generator_test(["abc"],
            ["abc", "Xabc", "aXbc", "abXc", "abcX"],
            "--typos-insert X --max-typos-insert 1 --typos 2 -d", True)
    def test_insert_min_1(self):
        self.do_generator_test(["abc"],
            ["Xabc", "aXbc", "abXc", "abcX", "XaXbc", "XabXc", "XabcX", "aXbXc", "aXbcX", "abXcX"],
            "--typos-insert X --typos 2 -d --min-typos 1", True)
    def test_insert_min_2(self):
        self.do_generator_test(["abc"],
            ["XaXbc", "XabXc", "XabcX", "aXbXc", "aXbcX", "abXcX"],
            "--typos-insert X --typos 2 -d --min-typos 2", True)
    def test_insert_min_5(self):
        self.do_generator_test(["abc"], [],
            "--typos-insert X --typos 5 -d --min-typos 5", True)
    def test_insert_adjacent_1(self):
        self.do_generator_test(["ab"], ["ab", "Xab", "aXb", "abX", "XXab", "XaXb", "XabX", "aXXb", "aXbX", "abXX"],
            "--typos-insert X --typos 2 --max-adjacent-inserts 2 -d", True)
    def test_insert_adjacent_2(self):
        self.do_generator_test(["a"], ["a", "Xa", "aX", "XXa", "XaX", "aXX", "XXaX", "XaXX" ],
            "--typos-insert X --typos 3 --max-adjacent-inserts 2 -d", True)
    def test_insert_wildcard(self):
        self.do_generator_test(["abc"], ["abc", "Xabc", "Yabc", "aXbc", "aYbc", "abXc", "abYc", "abcX", "abcY"],
            "--typos-insert %[XY] -d", True)
    def test_insert_wildcard_adjacent(self):
        self.do_generator_test(["a"],
            ["a", "Xa", "Ya", "aX", "aY", "XXa", "XYa", "YXa", "YYa",
             "XaX", "XaY", "YaX", "YaY", "aXX", "aXY", "aYX", "aYY"],
            "--typos-insert %[XY] --typos 2 --max-adjacent-inserts 2 -d", True)
    def test_insert_invalid(self):
        self.expect_syntax_failure(["abc"], "contracting wildcards are not permitted here",
            "--typos-insert %0,1-")

    def test_replace(self):
        self.do_generator_test(["abc"], ["abc", "Xbc", "aXc", "abX", "XXc", "XbX", "aXX"],
            "--typos-replace X --typos 2 -d", True)
    def test_replace_max(self):
        self.do_generator_test(["abc"], ["abc", "Xbc", "aXc", "abX"],
            "--typos-replace X --max-typos-replace 1 --typos 2 -d", True)
    def test_replace_wildcard(self):
        self.do_generator_test(["abc"], ["abc", "Xbc", "Ybc", "aXc", "aYc", "abX", "abY"],
            "--typos-replace %[X-Y] -d", True)
    def test_replace_invalid(self):
        self.expect_syntax_failure(["abc"], "contracting wildcards are not permitted here",
            "--typos-replace %>")

    def test_map(self):
        self.do_generator_test(["axb"],
            ["axb", "Axb", "Bxb", "axA", "axB", "AxA", "AxB", "BxA", "BxB"],
            "--typos-map __funccall --typos 2 -d", True,
            typos_map=StringIONonClosing(" ab \t AB \n x x \n a aB "))
    def test_map_max(self):
        self.do_generator_test(["axb"],
            ["axb", "Axb", "Bxb", "axA", "axB"],
            "--typos-map __funccall --max-typos-map 1 --typos 2 -d", True,
            typos_map=StringIONonClosing(" ab \t AB \n x x \n a aB "))

    def test_z_all(self):
        self.do_generator_test(["12"],
            list(map(tstr, [12,812,182,128,8812,8182,8128,1882,1828,1288,112,8112,1812,1182,
                1128,2,82,28,92,892,982,928,122,8122,1822,1282,1228,1,81,18,19,819,189,
                198,1122,11,119,22,"",9,922,9,99,21,821,281,218,221,1,91,211,2,29])),
            "--typos-swap --typos-repeat --typos-delete --typos-case --typos-insert 8 --typos-replace 9 --typos 2 --max-adjacent-inserts 2 -d",
            True)

    def test_z_all_max(self):
        self.do_generator_test(["12"],
            list(map(tstr, [12,812,182,128,112,8112,1812,1182,1128,2,82,28,92,892,982,928,122,8122,1822,
                1282,1228,1,81,18,19,819,189,198,11,119,22,9,922,9,21,821,281,218,221,1,91,211,2,29])),
            "--typos-swap --max-typos-swap 1 --typos-repeat --max-typos-repeat 1 --typos-delete --max-typos-delete 1 " + \
            "--typos-case --typos-insert 8 --max-typos-insert 1 --typos-replace 9 --max-typos-replace 1 --typos 2 -d",
            True)

    def test_z_min_typos_1(self):
        self.do_generator_test(["12"],
            list(map(tstr, [88182,88128,81882,81828,81288,18828,18288,88112,81812,81182,81128,
                18812,18182,18128,11882,11828,11288,882,828,288,8892,8982,8928,9882,9828,
                9288,88122,81822,81282,81228,18822,18282,18228,12882,12828,12288,881,818,
                188,8819,8189,8198,1889,1898,1988,81122,18122,11822,11282,11228,811,181,
                118,8119,1819,1189,1198,822,282,228,8,89,98,8922,9822,9282,9228,89,98,899,
                989,998,8821,8281,8218,2881,2818,2188,8221,2821,2281,2218,81,18,891,981,
                918,8211,2811,2181,2118,82,28,829,289,298,2211,22,229,11,"",9,911,9,99])),
            "--typos-swap --typos-repeat --typos-delete --typos-case --typos-insert 8 --typos-replace 9 --typos 3 --max-adjacent-inserts 2 --min-typos 3 -d",
            True)
    def test_z_min_typos_2(self):
        self.do_generator_test(["12"], [],
            "--typos-swap --typos-repeat --typos-delete --typos-case --typos-replace 8 --typos 4 -d --min-typos 4",
            True)


class Test05CommandLine(GeneratorTester):

    @classmethod
    def setUpClass(cls):
        cls.LARGE_TOKENLIST_LEN = 2 * btcrpass.PASSWORDS_BETWEEN_UPDATES
        cls.LARGE_TOKENLIST     = tstr(" ").join(tstr(i) for i in range(cls.LARGE_TOKENLIST_LEN))
        cls.LARGE_LAST_TOKEN    = tstr(cls.LARGE_TOKENLIST_LEN - 1)

    def test_embedded_tokenlist_option(self):
        self.do_generator_test(["#--typos-capslock", "one"], ["one", "ONE"])
    def test_embedded_tokenlist_overwridden_option(self):
        self.do_generator_test(["#--skip 1", "one two"], [], "--skip 2")
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_embedded_tokenlist_option_unicode(self):
        self.do_generator_test(["#--typos-insert в", "да"], ["да", "вда", "два", "дав"])
    def test_embedded_tokenlist_option_invalid(self):
        self.expect_syntax_failure(["#--tokenlist file"], "--tokenlist option is not permitted inside a tokenlist file")

    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_unicode(self):
        self.do_generator_test(["да"], ["да", "вда", "два", "дав"], "--typos-insert в")

    def test_passwordlist_no_wildcards(self):
        btcrpass.parse_arguments(("--passwordlist __funccall --listpass"+utf8_opt).split(),
                                 passwordlist = StringIO(tstr("%%")), disable_security_warning_param = True)
        tok_it, skipped = btcrpass.password_generator_factory(2)
        self.assertEqual(tok_it.__next__(), ["%%"])

    def test_regex_only(self):
        self.do_generator_test(["one", "two"], ["one", "twoone", "onetwo"], "--regex-only o.e")

    def test_regex_never(self):
        self.do_generator_test(["one", "two"], ["two"], "--regex-never o.e", True)

    def test_delimiter_tokenlist(self):
        self.do_generator_test(["", " one ** two **** "], [" one ", " two ", "", " "], "--delimiter **")

    def test_delimiter_typosmap(self):
        self.do_generator_test(["axb"], ["axb", "Axb", " xb", "axA", "ax ", "AxA", "Ax ", " xA", " x " ],
            "--delimiter ** --typos-map __funccall --typos 2 -d",
            True, typos_map=StringIONonClosing(tstr(" ab **A \n\n x **x")))

    # Try to test the myriad of --skip related boundary conditions in password_generator_factory()
    def test_skip(self):
        self.do_generator_test(["one", "two"], ["twoone", "onetwo"], "--skip 2", False, sys.maxsize, 2)
    def test_skip_all_exact(self):
        self.do_generator_test(["one"], [], "--skip 1", True, sys.maxsize, 1)
    def test_skip_all_pastend_1(self):
        self.do_generator_test(["one"], [], "--skip 2", True, sys.maxsize, 1)
    def test_skip_all_pastend_2(self):
        self.do_generator_test(["one"], [], "--skip " + str(self.LARGE_TOKENLIST_LEN), True, sys.maxsize, 1)
    def test_skip_empty_1(self):
        self.do_generator_test([], [], "--skip 1", True, sys.maxsize, 0)
    def test_skip_empty_2(self):
        self.do_generator_test([], [], "--skip " + str(self.LARGE_TOKENLIST_LEN), True, sys.maxsize, 0)
    def test_skip_large_1(self):
        self.do_generator_test([self.LARGE_TOKENLIST], [self.LARGE_LAST_TOKEN],
                               "-d --skip " + str(self.LARGE_TOKENLIST_LEN - 1),
                               False, sys.maxsize, self.LARGE_TOKENLIST_LEN - 1)
    def test_skip_large_1_all_exact(self):
        self.do_generator_test([self.LARGE_TOKENLIST], [],
                               "-d --skip " + str(self.LARGE_TOKENLIST_LEN),
                               False, sys.maxsize, self.LARGE_TOKENLIST_LEN)
    def test_skip_large_1_all_pastend(self):
        self.do_generator_test([self.LARGE_TOKENLIST], [],
                               "-d --skip " + str(self.LARGE_TOKENLIST_LEN + 1),
                               False, sys.maxsize, self.LARGE_TOKENLIST_LEN)
    def test_skip_large_2(self):
        self.do_generator_test([self.LARGE_TOKENLIST + " last"], ["last"],
                               "-d --skip " + str(self.LARGE_TOKENLIST_LEN),
                               False, sys.maxsize, self.LARGE_TOKENLIST_LEN)
    def test_skip_large_2_all_exact(self):
        self.do_generator_test([self.LARGE_TOKENLIST + " last"], [],
                               "-d --skip " + str(self.LARGE_TOKENLIST_LEN + 1),
                               False, sys.maxsize, self.LARGE_TOKENLIST_LEN + 1)
    def test_skip_large_2_all_pastend(self):
        self.do_generator_test([self.LARGE_TOKENLIST + " last"], [],
                               "-d --skip " + str(self.LARGE_TOKENLIST_LEN + 2),
                               False, sys.maxsize, self.LARGE_TOKENLIST_LEN + 1)
    def test_skip_end2end(self):
        btcrpass.parse_arguments(("--skip 2 --tokenlist __funccall --listpass"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("one \n two")), disable_security_warning_param = True)
        self.assertIn("2 password combinations (plus 2 skipped)", btcrpass.main()[1])
    def test_skip_end2end_all_exact(self):
        btcrpass.parse_arguments(("--skip 4 --tokenlist __funccall --listpass"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("one \n two")), disable_security_warning_param = True)
        self.assertIn("0 password combinations (plus 4 skipped)", btcrpass.main()[1])
    def test_skip_end2end_all_pastend(self):
        btcrpass.parse_arguments(("--skip 5 --tokenlist __funccall --listpass"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("one \n two")), disable_security_warning_param = True)
        self.assertIn("0 password combinations (plus 4 skipped)", btcrpass.main()[1])
    def test_skip_end2end_all_noeta(self):
        btcrpass.parse_arguments(("--skip 5 --tokenlist __funccall --no-eta --wallet __null"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("one \n two")), disable_security_warning_param = True)
        self.assertIn("Skipped all 4 passwords", btcrpass.main()[1])

    def test_max_eta(self):
        btcrpass.parse_arguments(("--max-eta 1 --tokenlist __funccall --wallet __null"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("1 2 3 4 5 6 7 8 9 10 11")), disable_security_warning_param = True)
        with self.assertRaises(SystemExit) as cm:
            btcrpass.count_and_check_eta(360.0)  # 360s * 11 passwords > 1 hour
        self.assertIn("at least 11 passwords to try, ETA > --max-eta option (1 hours)", cm.exception.code)
    def test_max_eta_ok(self):
        btcrpass.parse_arguments(("--max-eta 1 --tokenlist __funccall --wallet __null"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("1 2 3 4 5 6 7 8 9 10")), disable_security_warning_param = True)
        self.assertEqual(btcrpass.count_and_check_eta(360.0), 10)  # 360s * 10 passwords <= 1 hour
    def test_max_eta_skip(self):
        btcrpass.parse_arguments(("--max-eta 1 --skip 4 --tokenlist __funccall --wallet __null"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("1 2 3 4 5 6 7 8 9 10 11 12 13 14 15")), disable_security_warning_param = True)
        with self.assertRaises(SystemExit) as cm:
            btcrpass.count_and_check_eta(360.0)  # 360s * 11 passwords > 1 hour
        self.assertIn("at least 11 passwords to try, ETA > --max-eta option (1 hours)", cm.exception.code)
    def test_max_eta_skip_ok(self):
        btcrpass.parse_arguments(("--max-eta 1 --skip 5 --tokenlist __funccall --wallet __null"+utf8_opt).split(),
                                 tokenlist = StringIO(tstr("1 2 3 4 5 6 7 8 9 10 11 12 13 14 15")), disable_security_warning_param = True)
        # 360s * 10 passwords <= 1 hour, but count_and_check_eta still returns the total count of 15
        self.assertEqual(btcrpass.count_and_check_eta(360.0), 15)

    def test_worker_evensplit(self):
        self.do_generator_test(["one two three four five six seven eight"], ["one", "four", "seven"],
            "--worker 1/3")
        self.do_generator_test(["one two three four five six seven eight"], ["two", "five", "eight"],
            "--worker 2/3")
        self.do_generator_test(["one two three four five six seven eight"], ["three", "six"],
            "--worker 3/3")

    def test_worker_unevensplit(self):
        self.do_generator_test(["one two three four five six seven eight"], ["one", "two", "four", "five", "seven", "eight"],
            "--worker 1,2/3")
        self.do_generator_test(["one two three four five six seven eight"], ["two", "three", "five", "six", "eight"],
            "--worker 2,3/3")
        self.do_generator_test(["one two three four five six seven eight"], ["one", "two", "three", "four", "five", "six", "seven", "eight"],
            "--worker 1,2,3/3")

    def test_no_dupchecks_1(self):
        self.do_generator_test(["one", "one"], ["one", "one", "oneone", "oneone"], "-ddd")
        self.do_generator_test(["one", "one"], ["one", "one", "oneone"], "-dd")

    def test_no_dupchecks_2(self):
        self.do_generator_test(["one", "one"], ["one", "oneone"], "-d")
        # Duplicate code works differently the second time around; test it also
        self.assertEqual(btcrpass.password_generator(3).__next__(), ["one", "oneone"])

    def test_no_dupchecks_3(self):
        self.do_generator_test(["%[ab] %[a-b]"], ["a", "b", "a", "b"], "-d")
        self.do_generator_test(["%[ab] %[a-b]"], ["a", "b"])
        # Duplicate code works differently the second time around; test it also
        self.assertEqual(btcrpass.password_generator(3).__next__(), ["a", "b"])

    # Need to check four different code paths for --exclude-passwordlist
    def test_exclude(self):
        self.do_generator_test(["exc1 exc2 inc exc1 exc2"], ["inc"], "--exclude-passwordlist __funccall",
                               exclude_passwordlist=StringIO(tstr("exc1\nexc2")))
    def test_exclude_nodupchecks(self):
        self.do_generator_test(["exc1 exc2 inc exc1 exc2"], ["inc"], "--exclude-passwordlist __funccall -dd",
                               exclude_passwordlist=StringIO(tstr("exc1\nexc2")))
    def test_exclude_noeta(self):
        self.do_generator_test(["exc1 exc2 inc exc1 exc2"], ["inc"], "--exclude-passwordlist __funccall --no-eta",
                               exclude_passwordlist=StringIO(tstr("exc1\nexc2")))
    def test_exclude_noeta_nodupchecks(self):
        self.do_generator_test(["exc1 exc2 inc exc1 exc2"], ["inc"], "--exclude-passwordlist __funccall --no-eta -dd",
                               exclude_passwordlist=StringIO(tstr("exc1\nexc2")))


SAVESLOT_SIZE = 4096
class Test06AutosaveRestore(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.AUTOSAVE_ARGS = (
            tstr("--autosave __funccall --tokenlist __funccall --data-extract --no-progress --threads 1"+utf8_opt)).split()
        cls.AUTOSAVE_TOKENLIST    = tstr("^one \n two \n three \n")
        cls.AUTOSAVE_DATA_EXTRACT = "bWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA=="
        cls.autosave_file         = BytesIONonClosing()

    def run_autosave_parse_arguments(self, autosave_file):
        btcrpass.parse_arguments(self.AUTOSAVE_ARGS,
                                 autosave     = autosave_file,
                                 tokenlist    = StringIO(self.AUTOSAVE_TOKENLIST),
                                 data_extract = self.AUTOSAVE_DATA_EXTRACT,
                                 disable_security_warning_param = True)

    def run_restore_parse_arguments(self, restore_file):
        btcrpass.parse_arguments("--restore __funccall".split(),
                                 restore      = restore_file,
                                 tokenlist    = StringIO(self.AUTOSAVE_TOKENLIST),
                                 data_extract = self.AUTOSAVE_DATA_EXTRACT,
                                 disable_security_warning_param = True)

    # These test_ functions are in alphabetical order (the same order they're executed in)

    # Create the initial autosave data
    def test_autosave(self):
        autosave_file = self.autosave_file
        self.run_autosave_parse_arguments(autosave_file)
        self.assertIn(btcrpass.searchfailedtext, btcrpass.main()[1])
        #
        # Load slot 0, and verify it was created before any passwords were tested
        autosave_file.seek(0)
        savestate = pickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 0)
        self.assertLessEqual(autosave_file.tell(), SAVESLOT_SIZE)
        #
        # Load slot 1, and verify it was created after all passwords were tested
        autosave_file.seek(SAVESLOT_SIZE)
        savestate = pickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 9)
        self.assertLessEqual(autosave_file.tell(), 2*SAVESLOT_SIZE)

    # Using --autosave, restore (a copy of) the autosave data created by test_autosave(),
    # and make sure all of the passwords have already been tested
    def test_autosave_restore(self):
        self.run_autosave_parse_arguments(BytesIONonClosing(self.autosave_file.getvalue()))
        self.assertIn("Skipped all 9 passwords, exiting", btcrpass.main()[1])

    # Using --restore, restore (a copy of) the autosave data created by test_autosave(),
    # and make sure all of the passwords have already been tested
    def test_restore(self):
        self.run_restore_parse_arguments(BytesIONonClosing(self.autosave_file.getvalue()))
        self.assertIn("Skipped all 9 passwords, exiting", btcrpass.main()[1])

    # Using --autosave, restore (a copy of) the autosave data created by test_autosave(),
    # but change the arguments to generate an error
    def test_restore_changed_args(self):
        with self.assertRaises(SystemExit) as cm:
            btcrpass.parse_arguments(self.AUTOSAVE_ARGS + ["--typos-capslock"],
                                     autosave     = BytesIO(self.autosave_file.getvalue()),
                                     tokenlist    = StringIO(self.AUTOSAVE_TOKENLIST),
                                     data_extract = self.AUTOSAVE_DATA_EXTRACT,
                                     disable_security_warning_param = True)
        self.assertIn("Disallowed Arguments Difference:", cm.exception.code)

    # Using --autosave, restore (a copy of) the autosave data created by test_autosave(),
    # but change the tokenlist file to generate an error
    def test_restore_changed_tokenlist(self):
        with self.assertRaises(SystemExit) as cm:
            btcrpass.parse_arguments(self.AUTOSAVE_ARGS,
                                     autosave     = BytesIO(self.autosave_file.getvalue()),
                                     tokenlist    = StringIO(self.AUTOSAVE_TOKENLIST + "four"),
                                     data_extract = self.AUTOSAVE_DATA_EXTRACT,
                                     disable_security_warning_param = True)
        self.assertIn("can't restore previous session: the tokenlist file has changed", cm.exception.code)

    # Using --restore, restore (a copy of) the autosave data created by test_autosave(),
    # but change the data_extract to generate an error
    def test_restore_changed_data_extract(self):
        with self.assertRaises(SystemExit) as cm:
            btcrpass.parse_arguments("--restore __funccall".split(),
                                     restore      = BytesIO(self.autosave_file.getvalue()),
                                     tokenlist    = StringIO(self.AUTOSAVE_TOKENLIST),
                                     data_extract = "bWI6ACkebfNQTLk75CfI5X3svX6AC7NFeGsgUxKNFg==",
                                     disable_security_warning_param = True)  # has a valid CRC
        self.assertIn("can't restore previous session: the encrypted key entered is not the same", cm.exception.code)

    # Using --restore, restore the autosave data created by test_autosave(),
    # but remove the last byte from slot 1 to make it invalid
    def test_restore_truncated(self):
        autosave_file = self.autosave_file
        autosave_file.seek(-1, os.SEEK_END)
        autosave_file.truncate()
        self.run_restore_parse_arguments(autosave_file)
        #
        # Slot 1 had the final save, but since it is invalid, the loader should fall
        # back to slot 0 with the initial save, so the passwords should be tried again.
        self.assertIn(btcrpass.searchfailedtext, btcrpass.main()[1])
        #
        # Because slot 1 was invalid, it is the first slot overwritten. Load it, and
        # verify it was written to before any passwords were tested
        autosave_file.seek(SAVESLOT_SIZE)
        savestate = pickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 0)
        #
        # Load slot 0 (the second slot overwritten), and verify it was written to
        # after all passwords were tested
        autosave_file.seek(0)
        savestate = pickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 9)


is_pycrypto_loadable = None
def can_load_pycrypto():
    global is_pycrypto_loadable
    if is_pycrypto_loadable is None:
        print(warnings.filters)
        is_pycrypto_loadable = btcrpass.load_aes256_library().__name__ == "Crypto"
    return is_pycrypto_loadable

is_protobuf_loadable = None
def can_load_protobuf():
    global is_protobuf_loadable
    if is_protobuf_loadable is None:
        try:
            from .. import bitcoinj_pb2
            is_protobuf_loadable = True
        except ImportError:
            is_protobuf_loadable = False
    return is_protobuf_loadable

pylibscrypt = None
def can_load_scrypt():
    global pylibscrypt
    if pylibscrypt is None:
        try:
            from lib import pylibscrypt
        except ImportError:
            pylibscrypt = False
    return pylibscrypt and pylibscrypt._done  # True iff a binary implementation was found

is_sha3_loadable = None
def can_load_keccak():
    global is_sha3_loadable
    if is_sha3_loadable is None:
        try:
            from lib.eth_hash.auto import keccak
            keccak(b'')
            is_sha3_loadable = True
        except ImportError:
            is_sha3_loadable = False
    return is_sha3_loadable

is_coincurve_loadable = None
def can_load_coincurve():
    global is_coincurve_loadable
    if is_coincurve_loadable is None:
        try:
            import coincurve
            is_coincurve_loadable = True
        except ImportError:
            is_coincurve_loadable = False
    return is_coincurve_loadable

is_groestlcoin_hash_loadable = None
def can_load_groestlcoin_hash():
    global is_groestlcoin_hash_loadable
    if is_groestlcoin_hash_loadable is None:
        try:
            import groestlcoin_hash
            is_groestlcoin_hash_loadable = True
        except ImportError:
            is_groestlcoin_hash_loadable = False
    return is_groestlcoin_hash_loadable

is_ecdsa_loadable = None
def can_load_ecdsa():
    global is_ecdsa_loadable
    if is_ecdsa_loadable is None:
        try:
            import ecdsa
            is_ecdsa_loadable = True
        except ImportError:
            is_ecdsa_loadable = False
    return is_ecdsa_loadable

is_bitcoinutils_loadable = None
def can_load_bitcoinutils():
    global is_bitcoinutils_loadable
    if is_bitcoinutils_loadable is None:
        try:
            import bitcoinutils
            is_bitcoinutils_loadable = True
        except ImportError:
            is_bitcoinutils_loadable = False
    return is_bitcoinutils_loadable

is_eth_keyfile_loadable = None
def can_load_eth_keyfile():
    global is_eth_keyfile_loadable
    if is_eth_keyfile_loadable is None:
        try:
            import eth_keyfile
            is_eth_keyfile_loadable = True
        except ImportError:
            is_eth_keyfile_loadable = False
    return is_eth_keyfile_loadable

is_leveldb_loadable = None
def can_load_leveldb():
    global is_leveldb_loadable
    if is_leveldb_loadable is None:
        try:
            from lib.ccl_chrome_indexeddb import ccl_leveldb
            is_leveldb_loadable = True
        except:
            is_leveldb_loadable = False
    return is_leveldb_loadable

is_PyCryptoHDWallet_loadable = None
def can_load_PyCryptoHDWallet():
    global is_PyCryptoHDWallet_loadable
    if is_PyCryptoHDWallet_loadable is None:
        try:
            import py_crypto_hd_wallet
            is_PyCryptoHDWallet_loadable = True
        except:
            is_PyCryptoHDWallet_loadable = False
    return is_PyCryptoHDWallet_loadable

is_ShamirMnemonic_loadable = None
def can_load_ShamirMnemonic():
    global is_ShamirMnemonic_loadable
    if is_ShamirMnemonic_loadable is None:
        try:
            import shamir_mnemonic
            is_ShamirMnemonic_loadable = True
        except:
            is_ShamirMnemonic_loadable = False
    return is_ShamirMnemonic_loadable

eth2_staking_deposit_available = None
def can_load_staking_deposit():
    global eth2_staking_deposit_available
    if eth2_staking_deposit_available is None:
        try:
            from staking_deposit.key_handling.key_derivation.path import mnemonic_and_path_to_key
            from py_ecc.bls import G2ProofOfPossession as bls

            eth2_staking_deposit_available = True
        except:
            eth2_staking_deposit_available = False
    return eth2_staking_deposit_available

# Wrapper for btcrpass.init_worker() which clears btcrpass.loaded_wallet to simulate the way
# multiprocessing works on Windows (even on other OSs) and permits pure python library testing
def init_worker(wallet, char_mode, force_purepython, force_kdf_purepython):
    btcrpass.loaded_wallet = None
    btcrpass.init_worker(wallet, char_mode)
    if force_purepython:     btcrpass.load_aes256_library(force_purepython=True)
    if force_kdf_purepython: btcrpass.load_pbkdf2_library(force_purepython=True)


opencl_device_count = None
def has_any_opencl_devices():
    global opencl_device_count
    global opencl_devices_list
    if opencl_device_count is None:
        try:
            opencl_devices_list = list(btcrpass.get_opencl_devices())
        except ImportError:
            opencl_devices_list = ()
        opencl_device_count = len(opencl_devices_list)
    return opencl_device_count > 0

class Test07WalletDecryption(unittest.TestCase):

    # Checks a test wallet against the known password, and ensures
    # that the library doesn't make any changes to the wallet file
    def wallet_tester(self, arg_wallet_filename,
                      force_purepython = False, force_kdf_purepython = False, force_bsddb_purepython = False,
                      correct_pass = None, blockchain_mainpass = None, android_backuppass = None):
        wallet_filename = os.path.join(WALLET_DIR, arg_wallet_filename)
        temp_dir        = tempfile.mkdtemp("-test-btcr")
        parent_process  = True  # bug workaround, see finally block below for details
        try:
            temp_wallet_filename = os.path.join(temp_dir, os.path.basename(wallet_filename))
            try:
                shutil.copyfile(wallet_filename, temp_wallet_filename)
            except PermissionError:
                temp_wallet_filename = "./btcrecover/test/test-wallets/" + arg_wallet_filename

            except IsADirectoryError:
                temp_wallet_filename = "./btcrecover/test/test-wallets/" + arg_wallet_filename

            except FileNotFoundError:
                temp_wallet_filename = "./btcrecover/test/test-wallets/" + arg_wallet_filename


            if android_backuppass:
                wallet = btcrpass.WalletAndroidSpendingPIN.load_from_filename(
                    temp_wallet_filename, tstr(android_backuppass), force_purepython)
            elif blockchain_mainpass:
                wallet = btcrpass.WalletBlockchainSecondpass.load_from_filename(
                    temp_wallet_filename, tstr(blockchain_mainpass), force_purepython)
            elif force_bsddb_purepython:
                wallet = btcrpass.WalletBitcoinCore.load_from_filename(
                    temp_wallet_filename, force_bsddb_purepython)
            else:
                wallet = btcrpass.load_wallet(temp_wallet_filename)

            if force_purepython:     btcrpass.load_aes256_library(force_purepython=True)
            if force_kdf_purepython: btcrpass.load_pbkdf2_library(force_purepython=True)

            if not correct_pass:
                correct_pass = "btcr-test-password"

            # Perform the tests in the current process
            self.assertEqual(wallet.return_verified_password_or_false(
                (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
            self.assertEqual(wallet.return_verified_password_or_false(
                (tstr("btcr-wrong-password-3"), correct_pass, tstr("btcr-wrong-password-4"))), (correct_pass, 2))

            # Perform the tests in a child process to ensure the wallet can be pickled and all libraries reloaded
            parent_process = False
            pool = multiprocessing.Pool(1, init_worker, (wallet, tstr, force_purepython, force_kdf_purepython))
            parent_process = True
            password_found_iterator = pool.imap(btcrpass.return_verified_password_or_false,
                ( ( tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2") ),
                  ( tstr("btcr-wrong-password-3"), correct_pass, tstr("btcr-wrong-password-4") ) ))
            self.assertEqual(password_found_iterator.__next__(), (False, 2))
            self.assertEqual(password_found_iterator.__next__(), (correct_pass, 2))
            self.assertRaises(StopIteration, password_found_iterator.next)
            pool.close()
            pool.join()

            del wallet
            gc.collect()
        finally:
            # There's a bug which only occurs when combining unittest, multiprocessing, and "real"
            # forking (Linux/BSD/WSL); only remove the temp dir if we're sure this is the parent process
            if parent_process:
                shutil.rmtree(temp_dir)

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_bitcoincore_bdb(self):
        self.wallet_tester("bitcoincore-wallet.dat")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_bitcoincore_bdbhd(self):
        self.wallet_tester("bitcoincore-0.20.1-wallet.dat")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_bitcoincore_sqlite(self):
        self.wallet_tester("bitcoincore-0.21.1-wallet.dat")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_litecoincore(self):
        self.wallet_tester("litecoincore-0.18.1-wallet.dat")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_dogecoincore(self):
        self.wallet_tester("dogecoincore-1.14.2-wallet.dat")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_tenupcore(self):
        self.wallet_tester("tenup-1.1.0.4-wallet.dat")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_electrum(self):
        self.wallet_tester("electrum-wallet")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_electrum27(self):
        self.wallet_tester("electrum27-wallet")

    # A special case that tests an old wallet file that has been opened, but not unlocked in Electrum 4.x
    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_electrum27_updated_to_4(self):
            self.wallet_tester("electrum27-wallet-updated")

    def test_electrum27_multisig(self):
        self.wallet_tester("electrum27-multisig-wallet")

    def test_electrum27_loosekey(self):
        self.wallet_tester("electrum27-loosekey-wallet")

    def test_electrum2(self):
        self.wallet_tester("electrum2-wallet")

    def test_electrum2_upgradedfrom_electrum1(self):
        self.wallet_tester("electrum1-upgradedto-electrum2-wallet")

    def test_electrum2_loosekey(self):
        self.wallet_tester("electrum2-loosekey-wallet")

    def test_electrum27_upgradedfrom_electrum1(self):
        self.wallet_tester("electrum1-upgradedto-electrum27-wallet")

    @skipUnless(can_load_coincurve, "requires coincurve")
    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_electrum28(self):
        self.wallet_tester("electrum28-wallet")

    @skipUnless(can_load_coincurve, "requires coincurve")
    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_electrum41(self):
        self.wallet_tester("electrum41-wallet")

    @skipUnless(can_load_coincurve, "requires coincurve")
    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_electrum_100kbwallet(self):
        self.wallet_tester("electrum28-100kbwallet")

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_electrum28_pp(self):
        self.wallet_tester("electrum28-wallet", force_purepython=True)

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_multibit(self):
        self.wallet_tester("multibit-wallet.key")

    @skipUnless(can_load_protobuf, "requires protobuf")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_bitcoinj_multibit(self):
        self.wallet_tester("multibit.wallet.bitcoinj.encrypted")

    @skipUnless(can_load_protobuf, "requires protobuf")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_coinomi_android(self):
        self.wallet_tester("coinomi.wallet.android")

    @skipUnless(can_load_protobuf, "requires protobuf")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_coinomi_desktop(self):
        self.wallet_tester("coinomi.wallet.desktop")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_multidoge(self):
        self.wallet_tester("multidoge-wallet.key")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_dogecoin_wallet_android_backup(self):
        self.wallet_tester("dogecoin-wallet-android-backup")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    def test_multibithd(self):
        self.wallet_tester("mbhd.wallet.aes")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    def test_multibithd_v0_5_0(self):
        self.wallet_tester(os.path.join("multibithd-v0.5.0", "mbhd.wallet.aes"))

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    @skipUnless(can_load_protobuf, "requires protobuf")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    def test_bitcoinj(self):
        self.wallet_tester("bitcoinj-wallet.wallet")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    @skipUnless(can_load_protobuf, "requires protobuf")
    def test_android_bitcoin_wallet(self):
        self.wallet_tester("android-bitcoin-wallet-backup")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    @skipUnless(can_load_protobuf, "requires protobuf")
    def test_android_bitcoin_wallet_2022(self):
        self.wallet_tester("android-bitcoin-wallet-backup-2022")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    @skipUnless(can_load_protobuf, "requires protobuf")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    def test_androidpin(self):
        self.wallet_tester("android-bitcoin-wallet-backup",
                           android_backuppass="btcr-test-password", correct_pass="123456")

    @skipUnless(can_load_protobuf, "requires protobuf")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    def test_androidpin_unencrypted(self):
        self.wallet_tester("bitcoinj-wallet.wallet", android_backuppass="IGNORED")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    def test_bither(self):
        self.wallet_tester("bither-wallet.db")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    @skipUnless(can_load_scrypt,    "requires a binary implementation of pylibscrypt")
    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_bither_hdonly(self):
        self.wallet_tester("bither-hdonly-wallet.db")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_msigna(self):
        self.wallet_tester("msigna-wallet.vault")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_github_v1_1(self):
        self.wallet_tester("blockchain-github-v1-1", correct_pass="mypassword")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_github_v1_2(self):
        self.wallet_tester("blockchain-github-v1-2", correct_pass="mypassword")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_github_v1_3(self):
        self.wallet_tester("blockchain-github-v1-3", correct_pass="mypassword")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_blockchain_github_v2_1(self):
        self.wallet_tester("blockchain-github-v2-1", correct_pass="SomeTestPassword")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_blockchain_github_v2_2(self):
        self.wallet_tester("blockchain-github-v2-2", correct_pass="SomeTestPassword")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_blockchain_github_v3_1(self):
        self.wallet_tester("blockchain-github-v3-1", correct_pass="SomeTestPassword")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_blockchain_github_v3_2(self):
        self.wallet_tester("blockchain-github-v3-2", correct_pass="SomeTestPassword")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_github_v1_3_secondpass(self):
        self.wallet_tester("blockchain-github-v1-3", blockchain_mainpass="mypassword", correct_pass="mysecondpassword")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_v0_Jan2014(self):
        self.wallet_tester("blockchain-v0.0-Jan2014-wallet.aes.json", correct_pass="testblockchain")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_v3_Jan2021(self):
        self.wallet_tester("blockchain-v3.0-Jan2021-Android.json", correct_pass="Testing123!")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_v0(self):
        self.wallet_tester("blockchain-v0.0-wallet.aes.json")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_v3(self):
        self.wallet_tester("blockchain-v3.0-MAY2020-wallet.aes.json")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_v2(self):
        self.wallet_tester("blockchain-v2.0-wallet.aes.json")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_v4(self):
        self.wallet_tester("blockchain-v4.0-wallet.aes.json")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_secondpass_v0(self):
        self.wallet_tester("blockchain-v0.0-wallet.aes.json", blockchain_mainpass="btcr-test-password")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_secondpass_v2(self):
        self.wallet_tester("blockchain-v2.0-wallet.aes.json", blockchain_mainpass="btcr-test-password")

    def test_blockchain_secondpass_unencrypted(self):  # this wallet has no second-password iter_count, so this case is also tested here
        self.wallet_tester("blockchain-unencrypted-wallet.aes.json", blockchain_mainpass="IGNORED")

    def test_dogechain_info_cpu(self):
        self.wallet_tester("dogechain.wallet.aes.json")

    @skipUnless(can_load_ecdsa, "requires ECDSA")
    @skipUnless(can_load_bitcoinutils,  "requires Bitcoin-Utils")
    def test_block_io_privkeyrequest_data_legacy_cpu(self):
        self.wallet_tester("block.io.request.legacy.json", correct_pass="Anhday12")

    @skipUnless(can_load_ecdsa, "requires ECDSA")
    @skipUnless(can_load_bitcoinutils,  "requires Bitcoin-Utils")
    def test_block_io_privkeyrequest_data_cpu(self):
        self.wallet_tester("block.io.request.json", correct_pass="btcrtestpassword2022")

    @skipUnless(can_load_ecdsa, "requires ECDSA")
    @skipUnless(can_load_bitcoinutils,  "requires Bitcoin-Utils")
    def test_block_io_pinchange_data_cpu(self):
        self.wallet_tester("block.io.change.json", correct_pass="btcrtestpassword2022")

    @skipUnless(can_load_leveldb, "Unable to load LevelDB module, requires Python 3.8+")
    def test_metamask_leveldb_chrome_cpu(self):
        self.wallet_tester("metamask/nkbihfbeogaeaoehlefnkodbefgpgknn")

    @skipUnless(can_load_leveldb, "Unable to load LevelDB module, requires Python 3.8+")
    def test_metamask_v10_11_3_leveldb_chrome_cpu(self):
        self.wallet_tester("metamask/nkbihfbeogaeaoehlefnkodbefgpgknn-v10_11_3")

    def test_metamask_JSON_firefox_cpu(self):
        self.wallet_tester("metamask.9.8.4_firefox_vault")

    @skipUnless(can_load_leveldb, "Unable to load LevelDB module, requires Python 3.8+")
    def test_metamask_binancechainwallet_leveldb_cpu(self):
        self.wallet_tester("metamask/fhbohimaelbohpjbbldcngcnapndodjp", correct_pass="BTCR-test-passw0rd")

    @skipUnless(can_load_leveldb, "Unable to load LevelDB module, requires Python 3.8+")
    def test_metamask_ronin_leveldb_cpu(self):
        self.wallet_tester("metamask/fnjhmkhhmkbjkkabndcnnogagogbneec")

    def test_metamask_JSON_iOS_cpu(self):
        self.wallet_tester("metamask.ios.persist-root")

    def test_metamask_JSON_Android_cpu(self):
        self.wallet_tester("metamask.android.persist-root")

    def test_bitcoincore_pywallet(self):
        self.wallet_tester("bitcoincore-pywallet-dumpwallet.txt")

    @skipUnless(can_load_eth_keyfile, "requires Eth-Keyfile module")
    def test_eth_keystore_scrypt(self):
        self.wallet_tester("utc-keystore-v3-scrypt-myetherwallet.json")

    @skipUnless(can_load_eth_keyfile, "requires Eth-Keyfile module")
    def test_eth_keystore_pbkdf2(self):
        self.wallet_tester("utc-keystore-v3-pbkdf2-custom.json")

    @skipUnless(can_load_eth_keyfile, "requires Eth-Keyfile module")
    def test_imtoken_keystore(self):
        self.wallet_tester("imtoken-identity.json")

    # Make sure the Blockchain wallet loader can heuristically determine that files containing
    # base64 data that doesn't look entirely encrypted (random) are not Blockchain wallets
    def test_blockchain_invalid(self):
        # A base64-containing file that's mostly but not entirely encrypted (random)
        with self.assertRaises(ValueError) as cm:
            btcrpass.WalletBlockchain.load_from_filename(os.path.join(WALLET_DIR, "multibit-wallet.key"))
        self.assertIn("Doesn't look random enough to be an encrypted Blockchain wallet", cm.exception.args[0])

    def test_bitcoincore_pp(self):
        self.wallet_tester("bitcoincore-wallet.dat", force_purepython=True)

    def test_bitcoincore_no_bsddb(self):
        self.wallet_tester("bitcoincore-wallet.dat",  force_bsddb_purepython=True)

    def test_litecoincore_pp(self):
        self.wallet_tester("litecoincore-0.18.1-wallet.dat", force_purepython=True)

    def test_litecoincore_no_bsddb(self):
        self.wallet_tester("litecoincore-0.18.1-wallet.dat",  force_bsddb_purepython=True)

    def test_electrum_pp(self):
        self.wallet_tester("electrum-wallet", force_purepython=True)

    def test_electrum27_pp(self):
        self.wallet_tester("electrum27-wallet", force_purepython=True)

    def test_multibit_pp(self):
        self.wallet_tester("multibit-wallet.key", force_purepython=True)

    @skipUnless(can_load_scrypt, "requires a binary implementation of pylibscrypt")
    def test_multibithd_pp(self):
        self.wallet_tester("mbhd.wallet.aes", force_purepython=True)

    @skipUnless(can_load_protobuf, "requires protobuf")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    def test_bitcoinj_pp(self):
        self.wallet_tester("bitcoinj-wallet.wallet", force_purepython=True)

    @skipUnless(can_load_protobuf, "requires protobuf")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    def test_androidpin_pp(self):
        self.wallet_tester("android-bitcoin-wallet-backup", force_purepython=True,
                           android_backuppass="btcr-test-password", correct_pass="123456")

    @skipUnless(can_load_scrypt, "requires a binary implementation of pylibscrypt")
    def test_bither_pp(self):
        self.wallet_tester("bither-wallet.db", force_purepython=True)

    @skipUnless(can_load_scrypt,    "requires a binary implementation of pylibscrypt")
    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_bither_hdonly_pp(self):
        self.wallet_tester("bither-hdonly-wallet.db", force_purepython=True)

    def test_msigna_pp(self):
        self.wallet_tester("msigna-wallet.vault", force_purepython=True)

    def test_blockchain_v0_pp(self):
        self.wallet_tester("blockchain-v0.0-wallet.aes.json", force_purepython=True, force_kdf_purepython=True)

    def test_blockchain_v2_pp(self):
        self.wallet_tester("blockchain-v2.0-wallet.aes.json", force_purepython=True, force_kdf_purepython=True)

    def test_blockchain_v3_pp(self):
        self.wallet_tester("blockchain-v3.0-MAY2020-wallet.aes.json", force_purepython=True, force_kdf_purepython=True)

    def test_blockchain_secondpass_v0_pp(self):
        self.wallet_tester("blockchain-v0.0-wallet.aes.json", force_purepython=True, force_kdf_purepython=True,
                           blockchain_mainpass="btcr-test-password")

    def test_blockchain_secondpass_v2_pp(self):
        self.wallet_tester("blockchain-v2.0-wallet.aes.json", force_purepython=True, force_kdf_purepython=True,
                           blockchain_mainpass="btcr-test-password")

    def test_blockchain_secondpass_unencrypted_pp(self):  # this wallet has no second-password iter_count, so this case is also tested here
        self.wallet_tester("blockchain-unencrypted-wallet.aes.json", force_kdf_purepython=True, blockchain_mainpass="IGNORED")

    def test_invalid_wallet(self):
        with self.assertRaises(SystemExit) as cm:
            btcrpass.load_wallet(__file__)
        self.assertIn("unrecognized wallet format", cm.exception.code)

    @skipUnless(can_load_leveldb, "Unable to load LevelDB module, requires Python 3.8+")
    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_metamask_chrome_leveldb_OpenCL_Brute(self):
        wallet_filename = "./btcrecover/test/test-wallets/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn"

        btcrpass.loaded_wallet = btcrpass.WalletMetamask.load_from_filename(wallet_filename)

        btcrecover.opencl_helpers.auto_select_opencl_platform(btcrpass.loaded_wallet)

        btcrecover.opencl_helpers.init_opencl_contexts(btcrpass.loaded_wallet)

        self.assertEqual(btcrpass.WalletMetamask._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2")]), (False, 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " found a false positive")
        self.assertEqual(btcrpass.WalletMetamask._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-3"), tstr("btcr-test-password"), tstr("btcr-wrong-password-4")]), (tstr("btcr-test-password"), 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " failed to find password")

        del btcrpass.loaded_wallet

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_metamask_JSON_ios_OpenCL_Brute(self):
        wallet_filename = "./btcrecover/test/test-wallets/metamask.ios.persist-root"

        btcrpass.loaded_wallet = btcrpass.WalletMetamask.load_from_filename(wallet_filename)

        btcrecover.opencl_helpers.auto_select_opencl_platform(btcrpass.loaded_wallet)

        btcrecover.opencl_helpers.init_opencl_contexts(btcrpass.loaded_wallet)

        self.assertEqual(btcrpass.WalletMetamask._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2")]), (False, 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " found a false positive")
        self.assertEqual(btcrpass.WalletMetamask._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-3"), tstr("btcr-test-password"), tstr("btcr-wrong-password-4")]), (tstr("btcr-test-password"), 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " failed to find password")

        del btcrpass.loaded_wallet

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_blockchain_second_OpenCL_Brute(self):
        wallet_filename = os.path.join(WALLET_DIR, "blockchain-v2.0-wallet.aes.json")
        temp_dir        = tempfile.mkdtemp("-test-btcr")
        temp_wallet_filename = os.path.join(temp_dir, os.path.basename(wallet_filename))
        shutil.copyfile(wallet_filename, temp_wallet_filename)

        btcrpass.loaded_wallet = btcrpass.WalletBlockchainSecondpass.load_from_filename(temp_wallet_filename, password="btcr-test-password")

        btcrecover.opencl_helpers.auto_select_opencl_platform(btcrpass.loaded_wallet)

        btcrecover.opencl_helpers.init_opencl_contexts(btcrpass.loaded_wallet)

        self.assertEqual(btcrpass.WalletBlockchainSecondpass._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2")]), (False, 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " found a false positive")
        self.assertEqual(btcrpass.WalletBlockchainSecondpass._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-3"), tstr("btcr-test-password"), tstr("btcr-wrong-password-4")]), (tstr("btcr-test-password"), 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " failed to find password")

        del btcrpass.loaded_wallet

    def Electrum28_tester_OpenCL_Brute(self, walletfile):
        wallet_filename = os.path.join(WALLET_DIR, walletfile)
        temp_dir        = tempfile.mkdtemp("-test-btcr")
        temp_wallet_filename = os.path.join(temp_dir, os.path.basename(wallet_filename))
        shutil.copyfile(wallet_filename, temp_wallet_filename)

        btcrpass.loaded_wallet = btcrpass.load_wallet(temp_wallet_filename)

        btcrecover.opencl_helpers.auto_select_opencl_platform(btcrpass.loaded_wallet)

        btcrecover.opencl_helpers.init_opencl_contexts(btcrpass.loaded_wallet)

        self.assertEqual(btcrpass.WalletElectrum28._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2")]), (False, 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " found a false positive")
        self.assertEqual(btcrpass.WalletElectrum28._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-3"), tstr("btcr-test-password"), tstr("btcr-wrong-password-4")]), (tstr("btcr-test-password"), 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " failed to find password")

        del btcrpass.loaded_wallet

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_electrum28_OpenCL_Brute(self):
        self.Electrum28_tester_OpenCL_Brute("electrum28-wallet")

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_electrum41_OpenCL_Brute(self):
        self.Electrum28_tester_OpenCL_Brute("electrum41-wallet")

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_electrum28_100kbwallet_OpenCL_Brute(self):
        self.Electrum28_tester_OpenCL_Brute("electrum28-100kbwallet")

class Test08BIP39Passwords(unittest.TestCase):

    def bip39_tester_opencl(self, force_purepython = False, unicode_pw = False, *args, **kwargs):

        wallet = btcrpass.WalletBIP39(*args, **kwargs)
        if force_purepython: btcrpass.load_pbkdf2_library(force_purepython=True)

        btcrecover.opencl_helpers.auto_select_opencl_platform(wallet)

        btcrecover.opencl_helpers.init_opencl_contexts(wallet)

        # Perform the tests in the current process
        correct_pass = "btcr-test-password" if not unicode_pw else "btcr-тест-пароль"
        self.assertEqual(wallet._return_verified_password_or_false_opencl(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(wallet._return_verified_password_or_false_opencl(
            (tstr("btcr-wrong-password-3"), correct_pass, tstr("btcr-wrong-password-4"))), (correct_pass, 2))

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_bip39_mpk_opencl_brute(self):
        self.bip39_tester_opencl(
            mpk=      "xpub6D3uXJmdUg4xVnCUkNXJPCkk18gZAB8exGdQeb2rDwC5UJtraHHARSCc2Nz7rQ14godicjXiKxhUn39gbAw6Xb5eWb5srcbkhqPgAqoTMEY",
            mnemonic= "certain come keen collect slab gauge photo inside mechanic deny leader drop"
        )

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_Electrum2_mpk_opencl_brute(self):
        self.bip39_tester_opencl(
            wallet_type=   "Electrum2",
            mpk=     "zpub6oCYZXxa8YvFyR51r12U7q5B2cbeY25MqRnWTdXYex1EPuTvbfmeJmCFoo88xbqkgHyitfK1UW2q5CTPUW8fWqpZtsDF3jVwk6PTdGTbX2w",
            mnemonic=      "quote voice evidence aspect warfare hire system black rate wing ask rug"
        )

    def bip39_tester(self, force_purepython = False, unicode_pw = False, *args, **kwargs):

        wallet = btcrpass.WalletBIP39(*args, **kwargs)
        if force_purepython: btcrpass.load_pbkdf2_library(force_purepython=True)

        # Perform the tests in the current process
        correct_pass = "btcr-test-password" if not unicode_pw else "btcr-тест-пароль"
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-3"), correct_pass, tstr("btcr-wrong-password-4"))), (correct_pass, 2))

        # Perform the tests in a child process to ensure the wallet can be pickled and all libraries reloaded
        wallet.opencl = False
        pool = multiprocessing.Pool(1, init_worker, (wallet, tstr, force_purepython, False))
        password_found_iterator = pool.imap(btcrpass.return_verified_password_or_false,
            ( ( tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2") ),
              ( tstr("btcr-wrong-password-3"), correct_pass, tstr("btcr-wrong-password-4") ) ))
        self.assertEqual(password_found_iterator.__next__(), (False, 2))
        self.assertEqual(password_found_iterator.__next__(), (correct_pass, 2))
        self.assertRaises(StopIteration, password_found_iterator.next)
        pool.close()
        pool.join()

    def cardano_tester(self, *args, **kwargs):

        wallet = btcrpass.WalletCardano(*args, **kwargs)

        # Perform the tests in the current process
        correct_pass = "btcr-test-password"
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-3"), correct_pass, tstr("btcr-wrong-password-4"))), (correct_pass, 2))

        # Perform the tests in a child process to ensure the wallet can be pickled and all libraries reloaded
        wallet.opencl = False
        pool = multiprocessing.Pool(1, init_worker, (wallet, tstr, False, False))
        password_found_iterator = pool.imap(btcrpass.return_verified_password_or_false,
            ( ( tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2") ),
              ( tstr("btcr-wrong-password-3"), correct_pass, tstr("btcr-wrong-password-4") ) ))
        self.assertEqual(password_found_iterator.__next__(), (False, 2))
        self.assertEqual(password_found_iterator.__next__(), (correct_pass, 2))
        self.assertRaises(StopIteration, password_found_iterator.next)
        pool.close()
        pool.join()

    @unittest.skipUnless(can_load_staking_deposit(), "requires staking-deposit and py_ecc")
    def ethvalidator_tester(self, *args, **kwargs):

        wallet = btcrpass.WalletEthereumValidator(*args, **kwargs)

        # Perform the tests in the current process
        correct_pass = "btcr-test-password"
        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("btcr-wrong-password-3"), correct_pass, tstr("btcr-wrong-password-4"))), (correct_pass, 2))

        # Perform the tests in a child process to ensure the wallet can be pickled and all libraries reloaded
        wallet.opencl = False
        pool = multiprocessing.Pool(1, init_worker, (wallet, tstr, False, False))
        password_found_iterator = pool.imap(btcrpass.return_verified_password_or_false,
                                            ((tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2")),
                                             (tstr("btcr-wrong-password-3"), correct_pass,
                                              tstr("btcr-wrong-password-4"))))
        self.assertEqual(password_found_iterator.__next__(), (False, 2))
        self.assertEqual(password_found_iterator.__next__(), (correct_pass, 2))
        self.assertRaises(StopIteration, password_found_iterator.next)
        pool.close()
        pool.join()

    def WalletPyCryptoHDWallet_tester(self, correct_pass = "btcr-test-password", *args, **kwargs):

        wallet = btcrpass.WalletPyCryptoHDWallet(*args, **kwargs)

        # Perform the tests in the current process
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-3"), correct_pass, tstr("btcr-wrong-password-4"))), (correct_pass, 2))

        # Perform the tests in a child process to ensure the wallet can be pickled and all libraries reloaded
        wallet.opencl = False
        pool = multiprocessing.Pool(1, init_worker, (wallet, tstr, False, False))
        password_found_iterator = pool.imap(btcrpass.return_verified_password_or_false,
            ( ( tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2") ),
              ( tstr("btcr-wrong-password-3"), correct_pass, tstr("btcr-wrong-password-4") ) ))
        self.assertEqual(password_found_iterator.__next__(), (False, 2))
        self.assertEqual(password_found_iterator.__next__(), (correct_pass, 2))
        self.assertRaises(StopIteration, password_found_iterator.next)
        pool.close()
        pool.join()

    def WalletSLIP39_tester(self, correct_pass = "btcr-test-password", *args, **kwargs):

        wallet = btcrpass.WalletSLIP39(*args, **kwargs)

        # Perform the tests in the current process
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-3"), correct_pass, tstr("btcr-wrong-password-4"))), (correct_pass, 2))

        # Perform the tests in a child process to ensure the wallet can be pickled and all libraries reloaded
        wallet.opencl = False
        pool = multiprocessing.Pool(1, init_worker, (wallet, tstr, False, False))
        password_found_iterator = pool.imap(btcrpass.return_verified_password_or_false,
            ( ( tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2") ),
              ( tstr("btcr-wrong-password-3"), correct_pass, tstr("btcr-wrong-password-4") ) ))
        self.assertEqual(password_found_iterator.__next__(), (False, 2))
        self.assertEqual(password_found_iterator.__next__(), (correct_pass, 2))
        self.assertRaises(StopIteration, password_found_iterator.next)
        pool.close()
        pool.join()

    def cardano_tester_opencl(self, *args, **kwargs):

        wallet = btcrpass.WalletCardano(*args, **kwargs)

        btcrecover.opencl_helpers.auto_select_opencl_platform(wallet)

        btcrecover.opencl_helpers.init_opencl_contexts(wallet)

        # Perform the tests in the current process
        correct_pass = "btcr-test-password"
        self.assertEqual(wallet._return_verified_password_or_false_opencl(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(wallet._return_verified_password_or_false_opencl(
            (tstr("btcr-wrong-password-3"), correct_pass, tstr("btcr-wrong-password-4"))), (correct_pass, 2))

    def test_address_cardano_ledger(self):
        self.cardano_tester(
            addresses=  ["addr1qy0efqgj8vv85jlltlpjqe2sz4yuw27zqfczpcw8lavzq9flnqg3r29wezptgt8jzya9j5cya9jg4xgy3p7x9tcrqdmqfu7thk"],
            mnemonic=   "ocean hidden kidney famous rich season gloom husband spring convince attitude boy"
        )

    def test_address_cardano_trezor_12word(self):
        self.cardano_tester(
            addresses=  ["addr1q90kk6lsmk3fdy54mqfr50hy025ymnmn5hhj8ztthcv3qlzh5aynphrad3d26hzxg7xzzf8hnmdpxwtwums4nmryj3jqk8kvak"],
            mnemonic=   "ocean hidden kidney famous rich season gloom husband spring convince attitude boy"
        )


    # def test_address_cardano_trezor_24word(self):
    #     self.cardano_tester(
    #         addresses=  ["addr1qxy8p3rpnpnszuz3xjn7r220g0mls2s7y40u60856haqzvqugjuyvl52aplawmqtthwf98pusznhzy7m7v3vpy5tlydqpd86x9"],
    #         mnemonic=   "wood blame garbage one federal jaguar slogan movie thunder seed apology trigger spoon depth basket fine culture boil render special enforce dish middle antique"
    #     )

    def test_address_ethereumvalidator(self):
        self.ethvalidator_tester(
            addresses=  ["90c86e593885da004359fc6d1fe52e1b8210b0f46117c032d40a705cfeeda17bc0a5e8c85a4f46bd75c49100802976fd"],
            mnemonic=   "spatial evolve range inform burst screen session kind clap goat force sort",
            address_limit=2
        )

    @skipUnless(can_load_PyCryptoHDWallet, "requires Py_Crypto_HD_Wallet module")
    def test_address_PyCryptoHDWallet_solana(self):
        self.WalletPyCryptoHDWallet_tester(
            wallet_type="solana",
            address_limit=1,
            addresses=  ["8rYAgtkMvM1GmhLUTksAyEYyxC3ckwyGG7747FHFsn3y"],
            mnemonic=   "have hint welcome skate cinnamon rabbit cable payment gift uncover column duck scissors wedding decorate under marine hurry scrub rapid change roast print arch"
        )

    @skipUnless(can_load_PyCryptoHDWallet, "requires Py_Crypto_HD_Wallet module")
    def test_address_PyCryptoHDWallet_tron(self):
        self.WalletPyCryptoHDWallet_tester(
            wallet_type="tron",
            address_limit=1,
            addresses=  ["TGvJrj5D8qdzhcppg9RoLdfbEjDYCne8xc"],
            mnemonic=   "have hint welcome skate cinnamon rabbit cable payment gift uncover column duck scissors wedding decorate under marine hurry scrub rapid change roast print arch"
        )

    @skipUnless(can_load_PyCryptoHDWallet, "requires Py_Crypto_HD_Wallet module")
    def test_address_PyCryptoHDWallet_cosmos(self):
        self.WalletPyCryptoHDWallet_tester(
            wallet_type="cosmos",
            address_limit=1,
            addresses=  ["cosmos1djx4wh8zc9wdk5cwe3lawpmh0j4nsekej6mk9k"],
            mnemonic=   "doctor giant eternal huge improve suit service poem logic dynamic crane summer exhibit describe later suit dignity ahead unknown fall syrup mirror nurse season"
        )

    @skipUnless(can_load_PyCryptoHDWallet, "requires Py_Crypto_HD_Wallet module")
    def test_address_PyCryptoHDWallet_tezos(self):
        self.WalletPyCryptoHDWallet_tester(
            wallet_type="tezos",
            address_limit=1,
            addresses=  ["tz1WovCBe7yYsctWcqpw8pG5zfj6XpupYCh1"],
            mnemonic=   "cake return enhance slender swap butter code cram fashion warm uphold adapt swarm slight misery enhance almost ability artefact lava sugar regret example lake"
        )


    @skipUnless(can_load_PyCryptoHDWallet, "requires Py_Crypto_HD_Wallet module")
    def test_address_PyCryptoHDWallet_stellar(self):
        self.WalletPyCryptoHDWallet_tester(
            wallet_type="stellar",
            address_limit=2,
            addresses=  ["GBPYX2ELQ6YTAF7DXER7RCQJR2HXXFX6HUZKWEZD3B6RKOLDSJF7UGXK"],
            mnemonic=   "doctor giant eternal huge improve suit service poem logic dynamic crane summer exhibit describe later suit dignity ahead unknown fall syrup mirror nurse season"
        )

    @skipUnless(can_load_PyCryptoHDWallet, "requires Py_Crypto_HD_Wallet module")
    def test_address_PyCryptoHDWallet_avalanche(self):
        self.WalletPyCryptoHDWallet_tester(
            wallet_type="avalanche",
            address_limit=1,
            addresses=  ["X-avax170r6a4nwudym6tx494nxgdatpep2gvpm40h4tg"],
            mnemonic=   "have hint welcome skate cinnamon rabbit cable payment gift uncover column duck scissors wedding decorate under marine hurry scrub rapid change roast print arch"
        )

    @skipUnless(can_load_PyCryptoHDWallet, "requires Py_Crypto_HD_Wallet module")
    def test_address_PyCryptoHDWallet_polkadotsubstrate(self):
        self.WalletPyCryptoHDWallet_tester(
            path = ["//hard/soft"],
            correct_pass = "btcr-test-password",
            wallet_type="polkadotsubstrate",
            address_limit=1,
            addresses=  ["12uMBgecqfkHTYZE4GFRx847CwR7sfs2bTdPbPLpzeMDGFwC"],
            mnemonic=   "toilet assume drama keen dust warrior stick quote palace imitate music disease"
        )

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_address_cardano_ledger_opencl(self):
        self.cardano_tester_opencl(
            addresses=  ["addr1qy0efqgj8vv85jlltlpjqe2sz4yuw27zqfczpcw8lavzq9flnqg3r29wezptgt8jzya9j5cya9jg4xgy3p7x9tcrqdmqfu7thk"],
            mnemonic=   "ocean hidden kidney famous rich season gloom husband spring convince attitude boy"
        )

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_address_cardano_trezor_12word_opencl(self):
        self.cardano_tester_opencl(
            addresses=  ["addr1q90kk6lsmk3fdy54mqfr50hy025ymnmn5hhj8ztthcv3qlzh5aynphrad3d26hzxg7xzzf8hnmdpxwtwums4nmryj3jqk8kvak"],
            mnemonic=   "ocean hidden kidney famous rich season gloom husband spring convince attitude boy"
        )

    # @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    # def test_address_cardano_trezor_24word(self):
    #     self.cardano_tester_opencl(
    #         addresses=  ["addr1qxy8p3rpnpnszuz3xjn7r220g0mls2s7y40u60856haqzvqugjuyvl52aplawmqtthwf98pusznhzy7m7v3vpy5tlydqpd86x9"],
    #         mnemonic=   "wood blame garbage one federal jaguar slogan movie thunder seed apology trigger spoon depth basket fine culture boil render special enforce dish middle antique"
    #     )


    @skipUnless(can_load_ShamirMnemonic, "requires Shamir-Mnemonic module")
    def test_address_SLIP39_BTC(self):
        self.WalletSLIP39_tester(
            correct_pass = "btcr-test-password",
            wallet_type="bip39",
            address_limit=2,
            addresses=  ["bc1q76szkxz4cta5p5s66muskvads0nhwe5m5w07pq"],
            slip39_shares =   ["hearing echo academic acid deny bracelet playoff exact fancy various evidence standard adjust muscle parcel sled crucial amazing mansion losing",
                               "hearing echo academic agency deliver join grant laden index depart deadline starting duration loud crystal bulge gasoline injury tofu together"]
        )

    @skipUnless(can_load_ShamirMnemonic, "requires Shamir-Mnemonic module")
    def test_address_SLIP39_ETH(self):
        self.WalletSLIP39_tester(
            correct_pass = "btcr-test-password",
            wallet_type="ethereum",
            address_limit=2,
            addresses=  ["0x0Ef61684B1E671dcBee4D51646cA6247487Ef91a"],
            slip39_shares =   ["hearing echo academic acid deny bracelet playoff exact fancy various evidence standard adjust muscle parcel sled crucial amazing mansion losing",
                               "hearing echo academic agency deliver join grant laden index depart deadline starting duration loud crystal bulge gasoline injury tofu together"]
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_bip39_mpk(self):
        self.bip39_tester(
            mpk=      "xpub6D3uXJmdUg4xVnCUkNXJPCkk18gZAB8exGdQeb2rDwC5UJtraHHARSCc2Nz7rQ14godicjXiKxhUn39gbAw6Xb5eWb5srcbkhqPgAqoTMEY",
            mnemonic= "certain come keen collect slab gauge photo inside mechanic deny leader drop"
        )

    @skipUnless(can_load_coincurve,      "requires coincurve")
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_bip39_unicode_password(self):
        self.bip39_tester(
            mpk=        "xpub6CZe1G1A1CaaSepbekLMSk1sBRNA9kHZzEQCedudHAQHHB21FW9fYpQWXBevrLVQfL8JFQVFWEw3aACdr6szksaGsLiHDKyRd1rPJ6ev5ig",
            mnemonic=   "certain come keen collect slab gauge photo inside mechanic deny leader drop",
            unicode_pw= True
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_bip39_unicode_mnemonic(self):
        self.bip39_tester(
            mpk=       "xpub6C7cXo5w4HPs6X93zKdkRNDFyHedGHwQHvmMst7HYjeudySyF3eTsWktz6JVz4CkrzuLiEbieYP8dQaxsffJXjquD3FLmnqioHe8qZwcBF3",
            mnemonic= u"あんまり　おんがく　いとこ　ひくい　こくはく　あらゆる　てあし　げどく　はしる　げどく　そぼろ　はみがき"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_bip39_pp(self):
        self.bip39_tester(
            mpk=              "xpub6D3uXJmdUg4xVnCUkNXJPCkk18gZAB8exGdQeb2rDwC5UJtraHHARSCc2Nz7rQ14godicjXiKxhUn39gbAw6Xb5eWb5srcbkhqPgAqoTMEY",
            mnemonic=         "certain come keen collect slab gauge photo inside mechanic deny leader drop",
            force_purepython= True
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_bitcoin_bip44(self):
        self.bip39_tester(
            addresses=     ["1AmugMgC6pBbJGYuYmuRrEpQVB9BBMvCCn"],
            address_limit= 5,
            mnemonic=      "certain come keen collect slab gauge photo inside mechanic deny leader drop"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_bitcoin_bip49(self):
        self.bip39_tester(
            addresses=     ["34yrZYvhWEfVgZ8XFMuuwFeRpQ4m3u4EbY"],
            address_limit= 5,
            mnemonic=      "certain come keen collect slab gauge photo inside mechanic deny leader drop"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_bitcoin_bip84(self):
        self.bip39_tester(
            addresses=     ["bc1qj7najywjcjwd7ccn7kmeh3ckccwrslnrqrlnm7"],
            address_limit= 5,
            mnemonic=      "certain come keen collect slab gauge photo inside mechanic deny leader drop"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_bitcoin_mybitcoinwallet_single(self):
        self.bip39_tester(
            addresses=     ["1NLcraWZhG3wFBYX2zwkKwYztL6yyhJG32"],
            address_limit= 1,
            mnemonic = "spatial stereo thrive reform shallow blouse minimum foster eagle game answer worth size stumble theme crater bounce stay extra duty man weather awesome search",
            checksinglexpubaddress = True
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    @skipUnless(can_load_keccak,      "requires PyCryptoDomedome")
    def test_address_ethereum(self):
        self.bip39_tester(
            wallet_type=   "ethereum",
            addresses=     ["0x4daE22510CE2fE1BC81B97b31350Faf07c0A80D2"],
            address_limit= 3,
            mnemonic=      "cable top mango offer mule air lounge refuse stove text cattle opera"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_Zilliqa(self):
        self.bip39_tester(
            wallet_type=   "zilliqa",
            addresses=     ["zil1dcsu2uz0yczmunyk90e8g9sr5400c892yeh8fp"],
            address_limit= 1,
            mnemonic=      "cable top mango offer mule air lounge refuse stove text cattle opera"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_BCH(self):
        self.bip39_tester(
            wallet_type=   "bch",
            addresses=     ["bitcoincash:qqv8669jcauslc88ty5v0p7xj6p6gpmlgv04ejjq97"],
            address_limit= 3,
            mnemonic=      "cable top mango offer mule air lounge refuse stove text cattle opera"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_Dash(self):
        self.bip39_tester(
            wallet_type=   "dash",
            addresses=     ["XuTTeMZjUJuZGotrtTPRCmHCaxnX44a2aP"],
            address_limit= 3,
            mnemonic=      "cable top mango offer mule air lounge refuse stove text cattle opera"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_Dogecoin(self):
        self.bip39_tester(
            wallet_type=   "dogecoin",
            addresses=     ["DSTy3eptg18QWm6pCJGG4BvodSkj3KWvHx"],
            address_limit= 3,
            mnemonic=      "cable top mango offer mule air lounge refuse stove text cattle opera"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_Vertcoin(self):
        self.bip39_tester(
            wallet_type=   "vertcoin",
            addresses=     ["Vwodj33bXcT7K1uWbTqtk9UKymYSMeaXc3"],
            address_limit= 3,
            mnemonic=      "cable top mango offer mule air lounge refuse stove text cattle opera"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_Litecoin(self):
        self.bip39_tester(
            wallet_type=   "litecoin",
            addresses=     ["LdxLVMdt49CXcrnQRVJFRs8Yftu9dE8xxP"],
            address_limit= 3,
            mnemonic=      "cable top mango offer mule air lounge refuse stove text cattle opera"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_Monacoin(self):
        self.bip39_tester(
            wallet_type=   "monacoin",
            addresses=     ["MHLW7WdRKE1XBkLFS6oaTJE1nPCkD6acUd"],
            address_limit= 3,
            mnemonic=      "cable top mango offer mule air lounge refuse stove text cattle opera"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_DigiByte(self):
        self.bip39_tester(
            wallet_type=   "digibyte",
            addresses=     ["DNGbPa9QMbLgeVspu9jb6EEnXjJASMvA5r"],
            address_limit= 3,
            mnemonic=      "cable top mango offer mule air lounge refuse stove text cattle opera"
        )

    @skipUnless(can_load_groestlcoin_hash, "requires groestlcoin_hash")
    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_Groestlecoin(self):
        self.bip39_tester(
            wallet_type=   "groestlecoin",
            addresses=     ["FWzSMhK2TkotZodkApNxi4c6tvLUo7MBWk"],
            address_limit= 3,
            mnemonic=      "cable top mango offer mule air lounge refuse stove text cattle opera"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_Ripple(self):
        self.bip39_tester(
            wallet_type=   "Ripple",
            addresses=     ["rwv2s1wPjaCxmEFRm4j724yQ5Lh161mzwK"],
            address_limit= 3,
            mnemonic=      "cable top mango offer mule air lounge refuse stove text cattle opera"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_stacks(self):
        self.bip39_tester(
            wallet_type=   "Stacks",
            addresses=     ["SP2KJB4F9C91R3N5XSNQE0Z3G34DNJWQYTP3PBJTH"],
            address_limit= 2,
            mnemonic=      "ocean hidden kidney famous rich season gloom husband spring convince attitude boy"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_Electrum2_segwit(self):
        self.bip39_tester(
            wallet_type=   "Electrum2",
            addresses=     ["bc1q6n3u9aar3vgydfr6q23fzcfadh4zlp2ns2ljp6"],
            address_limit= 3,
            mnemonic=      "quote voice evidence aspect warfare hire system black rate wing ask rug"
        )

    @skipUnless(can_load_coincurve, "requires coincurve")
    def test_address_Electrum2_legacy(self):
        self.bip39_tester(
            wallet_type=   "Electrum2",
            addresses=     ["157yth95rdqsp6F3qbb12ejTnRimkQ7d5h"],
            address_limit= 3,
            mnemonic=      "water wait table horse smooth birth identify food favorite depend brother hand"
        )

class Test08KeyDecryption(unittest.TestCase):

    def key_tester(self, key_crc_base64, force_purepython = False, force_kdf_purepython = False, unicode_pw = False, correct_password = "btcr-test-password"):
        btcrpass.load_from_base64_key(key_crc_base64)
        if force_purepython:     btcrpass.load_aes256_library(force_purepython=True)
        if force_kdf_purepython: btcrpass.load_pbkdf2_library(force_purepython=True)

        correct_pw = tstr(correct_password) if not unicode_pw else "btcr-тест-пароль"
        self.assertEqual(btcrpass.return_verified_password_or_false(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(btcrpass.return_verified_password_or_false(
            (tstr("btcr-wrong-password-3"), correct_pw, tstr("btcr-wrong-password-4"))), (correct_pw, 2))

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_bitcoincore(self):
        self.key_tester("YmM65iRhIMReOQ2qaldHbn++T1fYP3nXX5tMHbaA/lqEbLhFk6/1Y5F5x0QJAQBI/maR")
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_pycrypto,       "requires PyCryptoDome")
    def test_bitcoincore_unicode(self):
        self.key_tester("YmM6XAL2X19VfzlKJfc+7LIeNrB2KC8E9DWe1YhhOchPoClvwftbuqjXKkfdAAARmggo", unicode_pw=True)

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_multibit(self):
        self.key_tester("bWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA==")
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_pycrypto,       "requires PyCryptoDome")
    def test_multibit_unicode(self):
        self.key_tester("bWI6YK6OX8bVP2Ar/j2dZBBQ+F0pEn8kZK6rlXiAWA==", unicode_pw=True)

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_multidoge(self):
        self.key_tester("bWI6IdK25nMhHI9n4zlb1cUtWBl7mL7gh7ZtxkYaDw==")
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_pycrypto,       "requires PyCryptoDome")
    def test_multidoge_unicode(self):
        self.key_tester("bWI6ry78W+RkeTi2dVt2omZMfXRi46xDsIhr0jKN3g==", unicode_pw=True)

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_androidwallet(self):
        self.key_tester("bWI6Ii/ZEeDjUJKq704wzUxKudpvAralnrOQtXM4og==")
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_pycrypto,       "requires PyCryptoDome")
    def test_androidwallet_unicode(self):
        self.key_tester("bWI6f1QdX7xXtC0zG7XK9pTGTifie5FUeAGhJ05esw==", unicode_pw=True)

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_androidknc(self):
        self.key_tester("bWI6n6ccPSkbrmxQpdfKNAOBFppQLGloPDHE2sOucQ====")
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_pycrypto,       "requires PyCryptoDome")
    def test_androidknc_unicode(self):
        self.key_tester("bWI6TaEiZOBE+52jqe09jKcVa39KqvOpJxbpEtCVPQ==", unicode_pw=True)

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    def test_multibithd(self):
        self.key_tester("bTU6LbH/+ROEa0cQ0inH7V3thcYVi5WL/4uGfU9/JQgsPZ6Y3zps")
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_pycrypto,       "requires PyCryptoDome")
    @skipUnless(can_load_scrypt,         "requires a binary implementation of pylibscrypt")
    def test_multibithd_unicode(self):
        self.key_tester("bTU6M7wXqwXQWo4o22eN50PNnsYVi5WL/4uGfU9/JQgsPZ42BGtS", unicode_pw=True)
    #
    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    def test_multibithd_v0_5_0(self):
        self.key_tester("bTU6Uh0pDwAKoBrKkMbf2ARxmyftdKB5dsqDUWTsD1fVrnsM2EYW")

    @skipUnless(can_load_protobuf, "requires protobuf")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_bitcoinj(self):
        self.key_tester("Ymo6MacXiCd1+6/qtPc5rCaj6qIGJbu5tX2PXQXqF4Df/kFrjNGMDMHqrwBAAAAIAAEAZwdBow==")
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_protobuf,       "requires protobuf")
    @skipUnless(can_load_scrypt,         "requires a binary implementation of pylibscrypt")
    @skipUnless(can_load_pycrypto,       "requires PyCryptoDome")
    def test_bitcoinj_unicode(self):
        self.key_tester("Ymo6hgWTejxVYfL/LLF4af8j2RfEsi5y16kTQhECWnn9iCt8AmGWPoPomQBAAAAIAAEAfNRA3A==", unicode_pw=True)

    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_bither(self):
        self.key_tester("YnQ6PocfHvWGVbCzlVb9cUtPDjosnuB7RoyspTEzZZAqURlCsLudQaQ4IkIW8YE=")
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_scrypt,         "requires a binary implementation of pylibscrypt")
    @skipUnless(can_load_pycrypto,       "requires PyCryptoDome")
    def test_bither_unicode(self):
        self.key_tester("YnQ6ENNU1KSJlzC8FMfAq/MHgWgaZkxpiByt/vLQ/UdP2NlCsLudQaQ4IjTbPcw=", unicode_pw=True)

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_msigna(self):
        self.key_tester("bXM6SWd6U+qTKOzQDfz8auBL1/tzu0kap7NMOqctt7U0nA8XOI6j6BCjxCsc7mU=")
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_pycrypto,       "requires PyCryptoDome")
    def test_msigna_unicode(self):
        self.key_tester("bXM6i9OkMzrIJqWvpM+Dxq795jeFFxiB6DtBwuGmeEtfHLLOjMvoJRAWeSsf+Pg=", unicode_pw=True)

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_electrum(self):
        self.key_tester("ZWw6kLJxTDF7LxneT7c5DblJ9k9WYwV6YUIUQO+IDiIXzMUZvsCT")
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_pycrypto,       "requires PyCryptoDome")
    def test_electrum_unicode(self):
        self.key_tester("ZWw6rLwP/stP422FgteriIgvq4LD90adedrAqz61gKuYDRrx3+Q+", unicode_pw=True)

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_electrum2(self):
        self.key_tester("ZTI69B961mYKYFV7Bg1zRYZ8ZGw4cE+2D8NF3lp6d2XPe8qTdJUz")
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_pycrypto,       "requires PyCryptoDome")
    def test_electrum2_unicode(self):
        self.key_tester("ZTI6k2tz83Lzs83hyQPRj2g90f7nVYHYM20qLv4NIVIzUNNqVWv8", unicode_pw=True)

    def test_electrum2_loosekey(self):
        self.key_tester("ZWs6FPx4P6wESVURM253BSUQvL8OMYotir0NptnEElninGsj4CuI")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_v0(self):
        self.key_tester("Yms69Z9y1J66ceYKkrXy11mHR+YDD8WrPJeTNaAnO7LO7YgAAAAAbnp7YQ==")
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_pycrypto,       "requires PyCryptoDome")
    def test_blockchain_v0_unicode(self):
        self.key_tester("Yms68OsennSoypcGGUvhrhEBFCiIkAK2Qphnfdc3Ungk/SoAAAAAcr6jYQ==", unicode_pw=True)

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_v2(self):
        self.key_tester("Yms6abF6aZYdu5sKpStKA4ihra6GEAeZTumFiIM0YQUkTjcQJwAAj8ekAQ==")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_blockchain_v3(self):
        self.key_tester("Yms6A6G5G+a+Q2Sm8GwZcojLJOJFk2tMKKhzmgjn28BZuE6IEwAA2s7F2Q==")

    def test_blockchain_secondpass(self):                # extracted from blockchain-v0.0-wallet.aes.json which has a second password iter_count
        self.key_tester("YnM6ujsYxz3SE7fEEekfMuIC1oII7KY//j5FMObBn7HydqVyjnaeTCZDAaC4LbJcVkxaCgAAACsWXkw=")
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_blockchain_secondpass_unicode(self):
        self.key_tester("YnM6/e8Inpbesj+CYE0YvdXLewgN5UH9KFvliZrI43OmYnyHbCa71RBD57XO0CbuADDTCgAAACCVL/w=", unicode_pw=True)

    def test_blockchain_secondpass_no_iter_count(self):  # extracted from blockchain-unencrypted-wallet.aes.json which is missing a second password iter_count
        self.key_tester("YnM6ujsYxz3SE7fEEekfMuIC1oII7KY//j5FMObBn7HydqVyjnaeTCZDAaC4LbJcVkxaAAAAAE/24yM=")

    @skipUnless(can_load_scrypt, "requires a binary implementation of pylibscrypt")
    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_coinomi(self):
        self.key_tester("Y246wmkdyRJJWG85XUTWYe9r9UUBkSrGN43WWUg5xXDelnEAGXs/lDcBMQBAAAAIAAEARsFrJw==")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_metamask_chrome(self):
        self.key_tester("bXQ6Ny6zeXCgltvFkIWycZU3gR/Ng61aKDp3Ue35NUiihsFzGnSlG2yDJQGOWXoyS1TYfJK5uu2cxo9cDBoGwA0DVgCUdDI1")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_metamask_firefox(self):
        self.key_tester("bXQ6bB5JP1EW0xwBmWZ9vI/iw9IRkorRs9rI6wJCNrd8KUw61ubkQxf9JF9jDv9kZIlxVVkKb7lIwnt7+519MLodzgA1vVjR")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_metamask_ronin(self):
        self.key_tester("bXQ6NFrMHOjRpTWv8X6Ofs9xFr9aCuHXqiBcn2cs+JnIV/Rz3e8cXASN3jCOCATGEfJqwATWFKP3CoAzETPxhc1e3gDSNsw1")

    @skipUnless(can_load_pycrypto,  "requires PyCryptoDome")
    def test_metamask_binancechainwallet(self):
        self.key_tester("bXQ6wTs1FXlOeMHlFE5++vK+HM3ZxgIeRn6YChp9zI7NtEnfrSKY8uVFIJpSsGOexEHbxr5uqUAH5ETrZSWjSFadggBvIHJ/", correct_password="BTCR-test-passw0rd")

    @skipUnless(can_load_pycrypto, "requires PyCryptoDome")
    def test_metamask_ios(self):
        self.key_tester("bXQ6oyvzsghbruyPSrkcEv0B+p7CkKODpMTPX8rpE3RV3HJ5d3Y0ZDNVeWpCdGpWUTBnaXAwU3dnPT0AAAAAAAAAAAFwj2d+")

    def test_bitcoincore_pp(self):
        self.key_tester("YmM65iRhIMReOQ2qaldHbn++T1fYP3nXX5tMHbaA/lqEbLhFk6/1Y5F5x0QJAQBI/maR", force_purepython=True)
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_bitcoincore_unicode_pp(self):
        self.key_tester("YmM6XAL2X19VfzlKJfc+7LIeNrB2KC8E9DWe1YhhOchPoClvwftbuqjXKkfdAAARmggo", force_purepython=True, unicode_pw=True)

    def test_multibit_pp(self):
        self.key_tester("bWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA==", force_purepython=True)
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_multibit_unicode_pp(self):
        self.key_tester("bWI6YK6OX8bVP2Ar/j2dZBBQ+F0pEn8kZK6rlXiAWA==", force_purepython=True, unicode_pw=True)

    def test_multidoge_pp(self):
        self.key_tester("bWI6IdK25nMhHI9n4zlb1cUtWBl7mL7gh7ZtxkYaDw==", force_purepython=True)
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_multidoge_unicode_pp(self):
        self.key_tester("bWI6ry78W+RkeTi2dVt2omZMfXRi46xDsIhr0jKN3g==", force_purepython=True, unicode_pw=True)

    def test_androidwallet_pp(self):
        self.key_tester("bWI6Ii/ZEeDjUJKq704wzUxKudpvAralnrOQtXM4og==", force_purepython=True)
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_androidwallet_unicode_pp(self):
        self.key_tester("bWI6f1QdX7xXtC0zG7XK9pTGTifie5FUeAGhJ05esw==", force_purepython=True, unicode_pw=True)

    def test_androidknc_pp(self):
        self.key_tester("bWI6n6ccPSkbrmxQpdfKNAOBFppQLGloPDHE2sOucQ==", force_purepython=True)
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_androidknc_unicode_pp(self):
        self.key_tester("bWI6TaEiZOBE+52jqe09jKcVa39KqvOpJxbpEtCVPQ==", force_purepython=True, unicode_pw=True)

    @skipUnless(can_load_scrypt, "requires a binary implementation of pylibscrypt")
    def test_multibithd_pp(self):
        self.key_tester("bTU6LbH/+ROEa0cQ0inH7V3thcYVi5WL/4uGfU9/JQgsPZ6Y3zps", force_purepython=True)
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_scrypt,         "requires a binary implementation of pylibscrypt")
    def test_multibithd_unicode_pp(self):
        self.key_tester("bTU6M7wXqwXQWo4o22eN50PNnsYVi5WL/4uGfU9/JQgsPZ42BGtS", force_purepython=True, unicode_pw=True)
    #
    @skipUnless(can_load_scrypt, "requires a binary implementation of pylibscrypt")
    def test_multibithd_v0_5_0_pp(self):
        self.key_tester("bTU6Uh0pDwAKoBrKkMbf2ARxmyftdKB5dsqDUWTsD1fVrnsM2EYW", force_purepython=True)

    @skipUnless(can_load_protobuf, "requires protobuf")
    @skipUnless(can_load_scrypt,   "requires a binary implementation of pylibscrypt")
    def test_bitcoinj_pp(self):
        self.key_tester("Ymo6MacXiCd1+6/qtPc5rCaj6qIGJbu5tX2PXQXqF4Df/kFrjNGMDMHqrwBAAAAIAAEAZwdBow==", force_purepython=True)
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_protobuf,       "requires protobuf")
    @skipUnless(can_load_scrypt,         "requires a binary implementation of pylibscrypt")
    def test_bitcoinj_unicode_pp(self):
        self.key_tester("Ymo6hgWTejxVYfL/LLF4af8j2RfEsi5y16kTQhECWnn9iCt8AmGWPoPomQBAAAAIAAEAfNRA3A==", force_purepython=True, unicode_pw=True)

    @skipUnless(can_load_scrypt, "requires a binary implementation of pylibscrypt")
    def test_bither_pp(self):
        self.key_tester("YnQ6PocfHvWGVbCzlVb9cUtPDjosnuB7RoyspTEzZZAqURlCsLudQaQ4IkIW8YE=", force_purepython=True)
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(can_load_scrypt,         "requires a binary implementation of pylibscrypt")
    def test_bither_unicode_pp(self):
        self.key_tester("YnQ6ENNU1KSJlzC8FMfAq/MHgWgaZkxpiByt/vLQ/UdP2NlCsLudQaQ4IjTbPcw=", force_purepython=True, unicode_pw=True)

    def test_msigna_pp(self):
        self.key_tester("bXM6SWd6U+qTKOzQDfz8auBL1/tzu0kap7NMOqctt7U0nA8XOI6j6BCjxCsc7mU=", force_purepython=True)
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_msigna_unicode_pp(self):
        self.key_tester("bXM6i9OkMzrIJqWvpM+Dxq795jeFFxiB6DtBwuGmeEtfHLLOjMvoJRAWeSsf+Pg=", force_purepython=True, unicode_pw=True)

    def test_electrum_pp(self):
        self.key_tester("ZWw6kLJxTDF7LxneT7c5DblJ9k9WYwV6YUIUQO+IDiIXzMUZvsCT", force_purepython=True)
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_electrum_unicode_pp(self):
        self.key_tester("ZWw6rLwP/stP422FgteriIgvq4LD90adedrAqz61gKuYDRrx3+Q+", force_purepython=True, unicode_pw=True)

    def test_electrum2_pp(self):
        self.key_tester("ZTI69B961mYKYFV7Bg1zRYZ8ZGw4cE+2D8NF3lp6d2XPe8qTdJUz", force_purepython=True)
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_electrum2_unicode_pp(self):
        self.key_tester("ZTI6k2tz83Lzs83hyQPRj2g90f7nVYHYM20qLv4NIVIzUNNqVWv8", force_purepython=True, unicode_pw=True)

    def test_blockchain_v0_pp(self):
        self.key_tester("Yms69Z9y1J66ceYKkrXy11mHR+YDD8WrPJeTNaAnO7LO7YgAAAAAbnp7YQ==", force_purepython=True, force_kdf_purepython=True)
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_blockchain_v0_unicode_pp(self):
        self.key_tester("Yms68OsennSoypcGGUvhrhEBFCiIkAK2Qphnfdc3Ungk/SoAAAAAcr6jYQ==", force_purepython=True, force_kdf_purepython=True, unicode_pw=True)

    def test_blockchain_v2_pp(self):
        self.key_tester("Yms6abF6aZYdu5sKpStKA4ihra6GEAeZTumFiIM0YQUkTjcQJwAAj8ekAQ==", force_purepython=True, force_kdf_purepython=True)

    def test_blockchain_v3(self):
        self.key_tester("Yms6A6G5G+a+Q2Sm8GwZcojLJOJFk2tMKKhzmgjn28BZuE6IEwAA2s7F2Q==", force_purepython=True, force_kdf_purepython=True)

    def test_blockchain_secondpass_pp(self):                # extracted from blockchain-v0.0-wallet.aes.json which has a second password iter_count
        self.key_tester("YnM6ujsYxz3SE7fEEekfMuIC1oII7KY//j5FMObBn7HydqVyjnaeTCZDAaC4LbJcVkxaCgAAACsWXkw=", force_kdf_purepython=True)
    #
    @skipUnless(lambda: tstr == str, "Unicode mode only")
    def test_blockchain_secondpass_unicode_pp(self):
        self.key_tester("YnM6/e8Inpbesj+CYE0YvdXLewgN5UH9KFvliZrI43OmYnyHbCa71RBD57XO0CbuADDTCgAAACCVL/w=", force_kdf_purepython=True, unicode_pw=True)

    def test_blockchain_secondpass_no_iter_count_pp(self):  # extracted from blockchain-unencrypted-wallet.aes.json which is missing a second password iter_count
        self.key_tester("YnM6ujsYxz3SE7fEEekfMuIC1oII7KY//j5FMObBn7HydqVyjnaeTCZDAaC4LbJcVkxaAAAAAE/24yM=", force_kdf_purepython=True)

    def init_opencl_kernel(self, devices, global_ws, int_rate = 200, **kwds):
        try:
            btcrpass.loaded_wallet.init_opencl_kernel(devices, global_ws, global_ws, int_rate, **kwds)
        except SystemExit as e:
            # this can happen with OpenCL CPUs whose max local-ws is 1, see #104
            if isinstance(e.code, str) and "local-ws" in e.code and "exceeds max" in e.code:
                btcrpass.loaded_wallet.init_opencl_kernel(devices, global_ws, [None] * len(global_ws), int_rate, **kwds)
            else:
                raise

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_bitcoincore_OpenCL_JTR(self):
        global opencl_devices_list
        btcrpass.load_from_base64_key("YmM65iRhIMReOQ2qaldHbn++T1fYP3nXX5tMHbaA/lqEbLhFk6/1Y5F5x0QJAQBI/maR")

        dev_names_tested = set()
        test_succeeded = False
        for dev in opencl_devices_list:
            if dev.name in dev_names_tested: continue
            if "oclgrind" in dev.name.lower(): continue # Skip testing on oclgrind device if present...
            dev_names_tested.add(dev.name)
            try:
                self.init_opencl_kernel([dev], [4])

                self.assertEqual(btcrpass.WalletBitcoinCore._return_verified_password_or_false_gpu(btcrpass.loaded_wallet,
                    [tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2")]), (False, 2),
                    dev.name.strip() + " found a false positive")
                self.assertEqual(btcrpass.WalletBitcoinCore._return_verified_password_or_false_gpu(btcrpass.loaded_wallet,
                    [tstr("btcr-wrong-password-3"), tstr("btcr-test-password"), tstr("btcr-wrong-password-4")]), (tstr("btcr-test-password"), 2),
                    dev.name.strip() + " failed to find password")

                test_succeeded = True

            except Exception as e:
                print(dev.name, " PyOpenCL Exception: ", e)

        self.assertTrue(test_succeeded) #Check that at least one device successfully ran the test

    @skipUnless(lambda: tstr == str, "Unicode mode only")
    @skipUnless(has_any_opencl_devices,  "requires OpenCL and a compatible device")
    def test_bitcoincore_OpenCL_JTR_unicode(self):
        global opencl_devices_list
        btcrpass.load_from_base64_key("YmM6XAL2X19VfzlKJfc+7LIeNrB2KC8E9DWe1YhhOchPoClvwftbuqjXKkfdAAARmggo")

        dev_names_tested = set()
        test_succeeded = False
        for dev in opencl_devices_list:
            if dev.name in dev_names_tested: continue
            if "oclgrind" in dev.name.lower(): continue  # Skip testing on oclgrind device if present...
            dev_names_tested.add(dev.name)
            try:
                self.init_opencl_kernel([dev], [4])

                self.assertEqual(btcrpass.WalletBitcoinCore._return_verified_password_or_false_gpu(btcrpass.loaded_wallet,
                    ["btcr-wrong-password-3", "btcr-тест-пароль", "btcr-wrong-password-4"]), ("btcr-тест-пароль", 2),
                    dev.name.strip() + " failed to find password")

                test_succeeded = True

            except Exception as e:
                print(dev.name, " PyOpenCL Exception: ", e)

        self.assertTrue(test_succeeded)  # Check that at least one device successfully ran the test

    @skipUnless(has_any_opencl_devices,          "requires OpenCL and a compatible device")
    def test_bitcoincore_OpenCL_JTR_low_interrupt_rate(self):
        global opencl_devices_list
        btcrpass.load_from_base64_key("YmM65iRhIMReOQ2qaldHbn++T1fYP3nXX5tMHbaA/lqEbLhFk6/1Y5F5x0QJAQBI/maR")

        dev_names_tested = set()
        test_succeeded = False
        for dev in opencl_devices_list:
            if dev.name in dev_names_tested: continue
            if "oclgrind" in dev.name.lower(): continue  # Skip testing on oclgrind device if present...
            dev_names_tested.add(dev.name)
            try:
                self.init_opencl_kernel([dev], [4], int_rate=10) #Interrupt rate defaults to 200

                self.assertEqual(btcrpass.WalletBitcoinCore._return_verified_password_or_false_gpu(btcrpass.loaded_wallet,
                    [tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2")]), (False, 2))
                self.assertEqual(btcrpass.WalletBitcoinCore._return_verified_password_or_false_gpu(btcrpass.loaded_wallet,
                    [tstr("btcr-wrong-password-3"), tstr("btcr-test-password"), tstr("btcr-wrong-password-4")]), (tstr("btcr-test-password"), 2))

                test_succeeded = True

            except Exception as e:
                print(dev.name, " PyOpenCL Exception: ", e)

        self.assertTrue(test_succeeded)  # Check that at least one device successfully ran the test


    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_bitcoincore_OpenCL_JTR_sli(self):
        global opencl_devices_list
        devices_by_name = dict()
        for dev in opencl_devices_list:
            if "oclgrind" in dev.name.lower(): continue  # Skip testing on oclgrind device if present...
            if dev.name in devices_by_name: break
            else: devices_by_name[dev.name] = dev
        else:
            self.skipTest("requires two identical OpenCL devices")

        test_succeeded = False
        btcrpass.load_from_base64_key("YmM65iRhIMReOQ2qaldHbn++T1fYP3nXX5tMHbaA/lqEbLhFk6/1Y5F5x0QJAQBI/maR")
        try:
            self.init_opencl_kernel([devices_by_name[dev.name], dev], [2, 2])

            self.assertEqual(btcrpass.WalletBitcoinCore._return_verified_password_or_false_gpu(btcrpass.loaded_wallet,
                [tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"), tstr("btcr-wrong-password-3"), tstr("btcr-wrong-password-4")]), (False, 4))
            self.assertEqual(btcrpass.WalletBitcoinCore._return_verified_password_or_false_gpu(btcrpass.loaded_wallet,
                [tstr("btcr-wrong-password-5"), tstr("btcr-test-password"), tstr("btcr-wrong-password-6")]), (tstr("btcr-test-password"), 2))
            self.assertEqual(btcrpass.WalletBitcoinCore._return_verified_password_or_false_gpu(btcrpass.loaded_wallet,
                [tstr("btcr-wrong-password-5"), tstr("btcr-wrong-password-6"), tstr("btcr-test-password")]), (tstr("btcr-test-password"), 3))

            test_succeeded = True

        except Exception as e:
            print(dev.name, " PyOpenCL Exception: ", e)

        self.assertTrue(test_succeeded)  # Check that at least one device successfully ran the test

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_bitcoincore_OpenCL_Brute(self):
        btcrpass.load_from_base64_key("YmM65iRhIMReOQ2qaldHbn++T1fYP3nXX5tMHbaA/lqEbLhFk6/1Y5F5x0QJAQBI/maR")

        btcrecover.opencl_helpers.auto_select_opencl_platform(btcrpass.loaded_wallet)

        btcrecover.opencl_helpers.init_opencl_contexts(btcrpass.loaded_wallet)

        self.assertEqual(btcrpass.WalletBitcoinCore._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2")]), (False, 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " found a false positive")
        self.assertEqual(btcrpass.WalletBitcoinCore._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-3"), tstr("btcr-test-password"), tstr("btcr-wrong-password-4")]), (tstr("btcr-test-password"), 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " failed to find password")

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_blockchain_main_OpenCL_Brute(self):
        btcrpass.load_from_base64_key("Yms6A6G5G+a+Q2Sm8GwZcojLJOJFk2tMKKhzmgjn28BZuE6IEwAA2s7F2Q==")

        btcrecover.opencl_helpers.auto_select_opencl_platform(btcrpass.loaded_wallet)

        btcrecover.opencl_helpers.init_opencl_contexts(btcrpass.loaded_wallet)

        self.assertEqual(btcrpass.WalletBlockchain._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2")]), (False, 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " found a false positive")
        self.assertEqual(btcrpass.WalletBlockchain._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-3"), tstr("btcr-test-password"), tstr("btcr-wrong-password-4")]), (tstr("btcr-test-password"), 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " failed to find password")

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_dogechain_info_OpenCL_Brute(self):
        btcrpass.load_from_base64_key("ZGM6jJzIUd6i9DMEgCFG9JQ1/z4xSamItXAiQnV4AeJ0BwcZznn+169Eb84PFQ3QQ2JGiBMAAGL+4VE=")

        btcrecover.opencl_helpers.auto_select_opencl_platform(btcrpass.loaded_wallet)

        btcrecover.opencl_helpers.init_opencl_contexts(btcrpass.loaded_wallet)

        self.assertEqual(btcrpass.WalletDogechain._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2")]), (False, 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " found a false positive")
        self.assertEqual(btcrpass.WalletDogechain._return_verified_password_or_false_opencl(btcrpass.loaded_wallet,
            [tstr("btcr-wrong-password-3"), tstr("btcr-test-password"), tstr("btcr-wrong-password-4")]), (tstr("btcr-test-password"), 2),
            "Platform:" + str(btcrpass.loaded_wallet.opencl_platform) + " failed to find password")


    def test_invalid_crc(self):
         with self.assertRaises(SystemExit) as cm:
             self.key_tester("aWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA==")
         self.assertIn("encrypted key data is corrupted (failed CRC check)", cm.exception.code)

class GPUTests(unittest.TestSuite) :
    def __init__(self):
        import os
        os.environ['PYOPENCL_COMPILER_OUTPUT'] = '1'
        super(GPUTests, self).__init__()
        self.addTest(unittest.defaultTestLoader.loadTestsFromNames(("Test08KeyDecryption." + method_name
            for method_name in (
                "test_bitcoincore_OpenCL_JTR",
                "test_bitcoincore_OpenCL_JTR_unicode",
                "test_bitcoincore_OpenCL_JTR_low_interrupt_rate",
                "test_bitcoincore_OpenCL_JTR_sli")),
            module=sys.modules[__name__]
        ))

class OpenCL_Tests(unittest.TestSuite) :
    def __init__(self):
        import os
        os.environ['PYOPENCL_COMPILER_OUTPUT'] = '1'
        super(OpenCL_Tests, self).__init__()
        self.addTest(unittest.defaultTestLoader.loadTestsFromNames(("Test08KeyDecryption." + method_name
            for method_name in (
                "test_bitcoincore_OpenCL_Brute",
                "test_blockchain_main_OpenCL_Brute")),
            module=sys.modules[__name__]
        ))
        self.addTest(unittest.defaultTestLoader.loadTestsFromNames(("Test07WalletDecryption." + method_name
            for method_name in (
                "test_blockchain_second_OpenCL_Brute",
                "test_electrum28_OpenCL_Brute")),
            module=sys.modules[__name__]
        ))
        self.addTest(unittest.defaultTestLoader.loadTestsFromNames(("Test08BIP39Passwords." + method_name
            for method_name in (
                "test_bip39_mpk_opencl_brute",
                "test_Electrum2_mpk_opencl_brute")),
            module=sys.modules[__name__]
        ))
        self.addTest(unittest.defaultTestLoader.loadTestsFromNames(("Test10YoroiWalletDecryption." + method_name
            for method_name in (
                ["test_yoroi_opencl_brute"])),
            module=sys.modules[__name__]
        ))

        self.addTest(unittest.defaultTestLoader.loadTestsFromNames(("Test11BIP38WalletDecryption." + method_name
            for method_name in (
                ["test_bip38_bitcoin_opencl_brute"])),
            module=sys.modules[__name__]
        ))



class Test09EndToEnd(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.E2E_ARGS         = tstr("--tokenlist __funccall --exclude-passwordlist __funccall --data-extract --autosave __funccall "
                                    "--typos 3 --typos-case --typos-repeat --typos-swap --threads 2 --no-progress"+utf8_opt).split()
        cls.E2E_TOKENLIST    = tstr("+ ^%0,1[b-c]tcr-- \n"  "+ ^,$%0,1<Test- \n"  "^3$pas \n"  "+ wrod$")
        cls.E2E_EXCLUDELIST  = tstr("tCr--Test-wrod\n" "btcr-Tsett-paaswrod\n" "ctcr--Test-pAssrwod")  # passwords #4, #100004, & #120004
        cls.E2E_DATA_EXTRACT = "bWI6oikebfNQTLk75CfI5X3svX6AC7NFeGsgTNXZfA=="
        cls.autosave_file    = BytesIONonClosing()

    # These test_ functions are in alphabetical order (the same order they're executed in)

    # A test of multiple features at once
    def test_end_to_end(self):
        autosave_file = self.autosave_file
        btcrpass.parse_arguments(self.E2E_ARGS,
                                 tokenlist            = StringIO(self.E2E_TOKENLIST),
                                 exclude_passwordlist = StringIO(self.E2E_EXCLUDELIST),
                                 data_extract         = self.E2E_DATA_EXTRACT,
                                 autosave             = autosave_file,
                                 disable_security_warning_param = True)
        self.assertEqual("btcr-test-password", btcrpass.main()[0])
        for process in multiprocessing.active_children():
            process.join()  # wait for any remaining child processes to exit cleanly

        # Verify the exact password number where it was found to ensure password ordering hasn't changed
        autosave_file.seek(SAVESLOT_SIZE)
        savestate = pickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 103762)

    # Repeat the test above using the same autosave file, starting off just before the password was found
    def test_restore(self):
        self.test_end_to_end()

        # Verify the password number where the search started
        autosave_file = self.autosave_file
        autosave_file.seek(0)
        savestate = pickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 103762)

    # Repeat the first test with a new autosave file, using --skip to start just after the password is located
    def test_skip(self):
        autosave_file = BytesIONonClosing()
        btcrpass.parse_arguments(self.E2E_ARGS + [tstr("--skip=103763")],
                                 tokenlist            = StringIO(self.E2E_TOKENLIST),
                                 exclude_passwordlist = StringIO(self.E2E_EXCLUDELIST),
                                 data_extract         = self.E2E_DATA_EXTRACT,
                                 autosave             = autosave_file,
                                 disable_security_warning_param = True)
        self.assertIn(btcrpass.searchfailedtext, btcrpass.main()[1])
        for process in multiprocessing.active_children():
            process.join()  # wait for any remaining child processes to exit cleanly

        # Verify the password number where the search started
        autosave_file.seek(0)
        savestate = pickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 103763)

        # Verify the total count of passwords
        autosave_file.seek(SAVESLOT_SIZE)
        savestate = pickle.load(autosave_file)
        self.assertEqual(savestate.get("skip"), 139652)

class Test10YoroiWalletDecryption(unittest.TestCase):

    test_master_password = b'A997F83D70BF83B32F8AC936AC32067653EE899979CCFDA67DFCBD535948C42A77DC' \
                           b'9E719BF4ECE7DEB18BA3CD86F53C5EC75DE2126346A791250EC09E570E8241EE4F84' \
                           b'0902CDFCBABC605ABFF30250BFF4903D0090AD1C645CEE4CDA53EA30BF419F4ECEA7' \
                           b'909306EAE4B671FA7EEE3C2F65BE1235DEA4433F20B97F7BB8933521C657C61BBE6C' \
                           b'031A7F1FEEF48C6978090ED009DD578A5382770A'

    def test_yoroi_cpu(self):

        wallet = btcrpass.WalletYoroi(self.test_master_password)

        correct_pw = tstr("btcr-test-password")
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-3"), correct_pw, tstr("btcr-wrong-password-4"))), (correct_pw, 2))

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_yoroi_opencl_brute(self):
        wallet = btcrpass.WalletYoroi(self.test_master_password)
        btcrecover.opencl_helpers.auto_select_opencl_platform(wallet)
        btcrecover.opencl_helpers.init_opencl_contexts(wallet)

        correct_pw = tstr("btcr-test-password")
        self.assertEqual(wallet._return_verified_password_or_false_opencl(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(wallet._return_verified_password_or_false_opencl(
            (tstr("btcr-wrong-password-3"), correct_pw, tstr("btcr-wrong-password-4"))), (correct_pw, 2))

class Test11BIP38WalletDecryption(unittest.TestCase):

    def bip38_tester_cpu(self, bip38_encrypted_key, bip38_network = 'bitcoin'):
        wallet = btcrpass.WalletBIP38(bip38_encrypted_key, bip38_network = bip38_network)

        correct_pw = tstr("btcr-test-password")
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-3"), correct_pw, tstr("btcr-wrong-password-4"))), (correct_pw, 2))

    def bip38_tester_opencl(self, bip38_encrypted_key, bip38_network = 'bitcoin'):
        wallet = btcrpass.WalletBIP38(bip38_encrypted_key, bip38_network = bip38_network)

        btcrecover.opencl_helpers.auto_select_opencl_platform(wallet)
        btcrecover.opencl_helpers.init_opencl_contexts(wallet)

        correct_pw = tstr("btcr-test-password")
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-3"), correct_pw, tstr("btcr-wrong-password-4"))), (correct_pw, 2))

    @skipUnless(can_load_ecdsa, "requires ecdsa")
    def test_bip38_bitcoin_cpu(self):
        self.bip38_tester_cpu('6PnM7h9sBC9EMZxLVsKzpafvBN8zjKp8MZj6h9mfvYEQRMkKBTPTyWZHHx')

    @skipUnless(can_load_ecdsa, "requires ecdsa")
    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_bip38_bitcoin_opencl_brute(self):
        self.bip38_tester_opencl('6PnM7h9sBC9EMZxLVsKzpafvBN8zjKp8MZj6h9mfvYEQRMkKBTPTyWZHHx')

    @skipUnless(can_load_ecdsa, "requires ecdsa")
    def test_bip38_litecoin_cpu(self):
        self.bip38_tester_cpu('6PfVHSTbgRNDaSwddBNgx2vMhMuNdiwRWjFgMGcJPb6J2pCG32SuL3vo6q',
                              bip38_network='litecoin')

    @skipUnless(can_load_ecdsa, "requires ecdsa")
    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_bip38_litecoin_opencl_brute(self):
        self.bip38_tester_opencl('6PfVHSTbgRNDaSwddBNgx2vMhMuNdiwRWjFgMGcJPb6J2pCG32SuL3vo6q',
                                 bip38_network='litecoin')

    @skipUnless(can_load_ecdsa, "requires ecdsa")
    def test_bip38_dash_cpu(self):
        self.bip38_tester_cpu('6PnZC9Snn1DHyvfEq9UKUmZwonqpfaWav6vRiSVNXXLUEDAuikZTxBUTEA',
                              bip38_network='dash')

    @skipUnless(can_load_ecdsa, "requires ecdsa")
    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_bip38_dash_opencl_brute(self):
        self.bip38_tester_opencl('6PnZC9Snn1DHyvfEq9UKUmZwonqpfaWav6vRiSVNXXLUEDAuikZTxBUTEA',
                                 bip38_network='dash')

class Test12BrainwalletDecryption(unittest.TestCase):

    def brainwallet_tester_cpu(self, addresses = None, check_compressed = True,
                               check_uncompressed = True, force_check_p2sh = False,
                               password = None, warpwallet = False, salt = None,
                               crypto='bitcoin'):

        wallet = btcrpass.WalletBrainwallet(addresses = [addresses],
                                            check_compressed = check_compressed,
                                            check_uncompressed = check_uncompressed,
                                            force_check_p2sh = force_check_p2sh,
                                            isWarpwallet=warpwallet,
                                            salt = salt,
                                            crypto=crypto)
        if password:
            correct_pw = password
        else:
            correct_pw = tstr("btcr-test-password")

        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(wallet._return_verified_password_or_false_cpu(
            (tstr("btcr-wrong-password-3"), correct_pw, tstr("btcr-wrong-password-4"))), (correct_pw, 2))

    def brainwallet_tester_opencl(self, addresses = None, check_compressed = True,
                               check_uncompressed = True, force_check_p2sh = False,
                                  password = None, warpwallet = False, salt = None,
                                  crypto='bitcoin'):

        wallet = btcrpass.WalletBrainwallet(addresses = [addresses],
                                            check_compressed = check_compressed,
                                            check_uncompressed = check_uncompressed,
                                            force_check_p2sh = force_check_p2sh,
                                            isWarpwallet=warpwallet,
                                            salt=salt,
                                            crypto=crypto)

        btcrecover.opencl_helpers.auto_select_opencl_platform(wallet)
        btcrecover.opencl_helpers.init_opencl_contexts(wallet)

        if password:
            correct_pw = password
        else:
            correct_pw = tstr("btcr-test-password")

        self.assertEqual(wallet._return_verified_password_or_false_opencl(
            (tstr("btcr-wrong-password-1"), tstr("btcr-wrong-password-2"))), (False, 2))
        self.assertEqual(wallet._return_verified_password_or_false_opencl(
            (tstr("btcr-wrong-password-3"), correct_pw, tstr("btcr-wrong-password-4"))), (correct_pw, 2))

    def test_brainwallet_bitcoin_p2pkh_compressed_cpu(self):
        self.brainwallet_tester_cpu(addresses = "1BBRWFHjFhEQc1iS6WTQCtPu2GtZvrRcwy",
                                    password="btcr-test-password:p2pkh",
                                    check_uncompressed=False)

    def test_brainwallet_bitcoin_p2pkh_uncompressed_cpu(self):
        self.brainwallet_tester_cpu(addresses="1MHoPPuGJyunUB5LZQF5dXTrLboEdxTmUm",
                                    password="btcr-test-password:p2pkh",
                                    check_compressed=False)

    def test_brainwallet_bitcoin_p2sh_compressed_cpu(self):
        self.brainwallet_tester_cpu(addresses = "3C4dEdngg4wnmwDYSwiDLCweYawMGg8dVN",
                                    password="btcr-test-password:p2wpkh-p2sh",
                                    check_uncompressed=False)

    def test_brainwallet_bitcoin_p2wpkh_compressed_cpu(self):
        self.brainwallet_tester_cpu(addresses="bc1qth4w90jmh0a6ug6pwsuyuk045fmtwzreg03gvj",
                                    password="btcr-test-password:p2wpkh",
                                        check_uncompressed=False)

    def test_brainwallet_litecoin_p2pkh_uncompressed_cpu(self):
        self.brainwallet_tester_cpu(addresses = "LfWkecD6Pe9qiymVjYENuYXcYpAWjU3mXw",
                                    password="btcr-test-password:p2pkh",
                                    check_compressed=False)

    def test_brainwallet_dash_p2pkh_uncompressed_cpu(self):
        self.brainwallet_tester_cpu(addresses = "XvyeDeZAGh8Nd7fvRHZJV49eAwNvfCubvB",
                                    password="btcr-test-password:p2pkh",
                                    check_compressed=False)

    def test_brainwallet_dash_p2pkh_compressed_cpu(self):
        self.brainwallet_tester_cpu(addresses = "XksGLVwdDQSzkxK1xPmd4R5grcUFyB3ouY",
                                    password="btcr-test-password:p2pkh",
                                    check_uncompressed=False)

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_brainwallet_bitcoin_p2pkh_compressed_opencl(self):
        self.brainwallet_tester_opencl(addresses = "1BBRWFHjFhEQc1iS6WTQCtPu2GtZvrRcwy",
                                    password="btcr-test-password:p2pkh",
                                    check_uncompressed=False)

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_brainwallet_bitcoin_p2pkh_uncompressed_opencl(self):
        self.brainwallet_tester_opencl(addresses="1MHoPPuGJyunUB5LZQF5dXTrLboEdxTmUm",
                                    password="btcr-test-password:p2pkh",
                                    check_compressed=False)

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_brainwallet_bitcoin_p2sh_compressed_opencl(self):
        self.brainwallet_tester_opencl(addresses = "3C4dEdngg4wnmwDYSwiDLCweYawMGg8dVN",
                                    password="btcr-test-password:p2wpkh-p2sh",
                                    check_uncompressed=False)

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_brainwallet_bitcoin_p2wpkh_compressed_opencl(self):
        self.brainwallet_tester_opencl(addresses="bc1qth4w90jmh0a6ug6pwsuyuk045fmtwzreg03gvj",
                                    password="btcr-test-password:p2wpkh",
                                        check_uncompressed=False)

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_brainwallet_litecoin_p2pkh_uncompressed_opencl(self):
        self.brainwallet_tester_opencl(addresses = "LfWkecD6Pe9qiymVjYENuYXcYpAWjU3mXw",
                                    password="btcr-test-password:p2pkh",
                                    check_compressed=False)

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_brainwallet_dash_p2pkh_uncompressed_opencl(self):
        self.brainwallet_tester_opencl(addresses = "XvyeDeZAGh8Nd7fvRHZJV49eAwNvfCubvB",
                                    password="btcr-test-password:p2pkh",
                                    check_compressed=False)

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_brainwallet_dash_p2pkh_compressed_opencl(self):
        self.brainwallet_tester_opencl(addresses = "XksGLVwdDQSzkxK1xPmd4R5grcUFyB3ouY",
                                    password="btcr-test-password:p2pkh",
                                    check_uncompressed=False)

    def test_brainwallet_warpwallet_bitcoin_cpu(self):
        self.brainwallet_tester_cpu(addresses = "1FThrDFjhSf8s1Aw2ed5U2sTrMz7HicZun",
                                    password="btcr-test-password",
                                    warpwallet = True,
                                    salt="btcr-test-password",
                                    check_compressed=False)

    def test_brainwallet_warpwallet_litecoin_cpu(self):
        self.brainwallet_tester_cpu(addresses = "LeBzGzZFxRUzzRAtm8EB2Dw74jRfQqUZeq",
                                    password="btcr-test-password",
                                    warpwallet = True,
                                    salt="btcr-test-password",
                                    crypto = "litecoin",
                                    check_compressed=False)

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_brainwallet_warpwallet_bitcoin_opencl(self):
        self.brainwallet_tester_opencl(addresses = "1FThrDFjhSf8s1Aw2ed5U2sTrMz7HicZun",
                                    password="btcr-test-password",
                                    warpwallet = True,
                                    salt="btcr-test-password",
                                    check_compressed=False)

    @skipUnless(has_any_opencl_devices, "requires OpenCL and a compatible device")
    def test_brainwallet_warpwallet_litecoin_opencl(self):
        self.brainwallet_tester_opencl(addresses = "LeBzGzZFxRUzzRAtm8EB2Dw74jRfQqUZeq",
                                    password="btcr-test-password",
                                    warpwallet = True,
                                    salt="btcr-test-password",
                                    crypto = "litecoin",
                                    check_compressed=False)

# Raw Private Key Wallets
class Test13RawPrivateKeyRecovery(unittest.TestCase):
    def test_rawprivatekey_Eth(self):
        wallet = btcrpass.WalletRawPrivateKey(addresses=['0xB9644424F9E639D1D0F27C4897e696CC324948BB'],
                                            check_compressed=True,
                                            check_uncompressed=True,
                                            force_check_p2sh=False,
                                            crypto='ethereum')

        correct_pw = tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d33")

        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d34"), tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d35"))), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d36"), correct_pw, tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d37"))), (correct_pw, 2))

    def test_rawprivatekey_Btc_legacy_Hex_Compressed(self):
        wallet = btcrpass.WalletRawPrivateKey(addresses=['1KoHUH6vf9MGRvooN7bHqrWghDqKc566tB'],
                                            check_compressed=True,
                                            check_uncompressed=True,
                                            force_check_p2sh=False,
                                            crypto='bitcoin')

        correct_pw = tstr("1ADF94484E9C820D69BC9770542B678DB677E7C354DC4BD27D7E9AC351698CB7")

        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d34"), tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d35"))), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d36"), correct_pw, tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d37"))), (correct_pw, 2))

    def test_rawprivatekey_Btc_legacy_Hex_Uncompressed(self):
        wallet = btcrpass.WalletRawPrivateKey(addresses=['1N8pQZkmrKjzSwuYFzThiMr8Ceg2mX4tAo'],
                                            check_compressed=True,
                                            check_uncompressed=True,
                                            force_check_p2sh=False,
                                            crypto='bitcoin')

        correct_pw = tstr("1ADF94484E9C820D69BC9770542B678DB677E7C354DC4BD27D7E9AC351698CB7")

        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d34"), tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d35"))), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d36"), correct_pw, tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d37"))), (correct_pw, 2))

    def test_rawprivatekey_Btc_p2sh_Hex_Compressed(self):
        wallet = btcrpass.WalletRawPrivateKey(addresses=['3AZyE1Dobb71DWjvYtSNqwNELPGQhdjqp4'],
                                            check_compressed=True,
                                            check_uncompressed=False,
                                            force_check_p2sh=True,
                                            crypto='bitcoin')

        correct_pw = tstr("1ADF94484E9C820D69BC9770542B678DB677E7C354DC4BD27D7E9AC351698CB7")

        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d34"), tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d35"))), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d36"), correct_pw, tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d37"))), (correct_pw, 2))

    def test_rawprivatekey_Btc_nativesegwit_Hex_Compressed(self):
        wallet = btcrpass.WalletRawPrivateKey(addresses=['bc1qecejtf3csl8gmjxvjmh0mwtqah8z7eetrcay67'],
                                            check_compressed=True,
                                            check_uncompressed=True,
                                            force_check_p2sh=False,
                                            crypto='bitcoin')

        correct_pw = tstr("1ADF94484E9C820D69BC9770542B678DB677E7C354DC4BD27D7E9AC351698CB7")

        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d34"), tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d35"))), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d36"), correct_pw, tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d37"))), (correct_pw, 2))

    def test_rawprivatekey_Btc_legacy_WIF_Uncompressed(self):
        wallet = btcrpass.WalletRawPrivateKey(addresses=['1EDrqbJMVwjQ2K5avN3627NcAXyWbkpGBL'],
                                            check_compressed=False,
                                            check_uncompressed=True,
                                            force_check_p2sh=False,
                                            crypto='bitcoin')

        correct_pw = tstr("5JYsdUthE1KzGAUXwfomeocw6vwzoTNXzcbJq9e7LcAyt1Svoo8")

        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d34"), tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d35"))), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d36"), correct_pw, tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d37"))), (correct_pw, 2))

    def test_rawprivatekey_Btc_legacy_WIF_Compressed(self):
        wallet = btcrpass.WalletRawPrivateKey(addresses=['1NMnWwgsaLaV97m3Z3PAkCvAyJqdVKHnEE'],
                                            check_compressed=True,
                                            check_uncompressed=False,
                                            force_check_p2sh=False,
                                            crypto='bitcoin')

        correct_pw = tstr("KzTgU27AYQSojvpXaJHS5rmboB7k83Q3oCDGAeoD3Rz2BbLFoP19")

        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d34"), tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d35"))), (False, 2))
        self.assertEqual(wallet.return_verified_password_or_false(
            (tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d36"), correct_pw, tstr("5db77aa7aea5ea7d6b4c64dab219972cf4763d4937d3e6e17f580436dcb10d37"))), (correct_pw, 2))


# QuickTests: all of Test01Basics, Test02Anchors, Test03WildCards, and Test04Typos,
# all of Test05CommandLine except the "large" tests, and select quick tests from
# Test08KeyDecryption
class QuickTests(unittest.TestSuite) :
    def __init__(self):
        super(QuickTests, self).__init__()
        tl = unittest.defaultTestLoader
        self.addTests(tl.loadTestsFromTestCase(TestCase)
            for TestCase in (Test01Basics, Test02Anchors, Test03WildCards, Test04Typos))
        self.addTest(tl.loadTestsFromNames(("Test05CommandLine." + method_name
            for method_name in tl.getTestCaseNames(Test05CommandLine) if "large" not in method_name),
            module=sys.modules[__name__]))
        self.addTest(tl.loadTestsFromNames(("Test08KeyDecryption." + method_name
            for method_name in (
                "test_bitcoincore_pp",
                "test_bitcoincore_unicode_pp",
                "test_multibit",
                "test_multibit_unicode",
                "test_multidoge",
                "test_multidoge_unicode",
                "test_androidwallet",
                "test_androidwallet_unicode",
                "test_androidknc",
                "test_androidknc_unicode",
                "test_multibithd",
                "test_multibithd_unicode",
                "test_multibithd_v0_5_0",
                "test_bitcoinj",
                "test_bitcoinj_unicode",
                "test_bither",
                "test_bither_unicode",
                "test_msigna",
                "test_msigna_unicode",
                "test_electrum",
                "test_electrum_unicode",
                "test_electrum2",
                "test_electrum2_unicode",
                "test_electrum2_loosekey",
                "test_blockchain_v0",
                "test_blockchain_v0_unicode",
                "test_blockchain_v2",
                "test_blockchain_secondpass",
                "test_blockchain_secondpass_unicode",
                "test_blockchain_secondpass_no_iter_count",
                "test_multibit_pp",
                "test_multibit_unicode_pp",
                "test_multidoge_pp",
                "test_multidoge_unicode_pp",
                "test_androidwallet_pp",
                "test_androidwallet_unicode_pp",
                "test_androidknc_pp",
                "test_androidknc_unicode_pp",
                "test_multibithd_pp",
                "test_multibithd_unicode_pp",
                "test_multibithd_v0_5_0_pp",
                "test_bitcoinj_pp",
                "test_bitcoinj_unicode_pp",
                "test_bither_pp",
                "test_bither_unicode_pp",
                "test_msigna_pp",
                "test_msigna_unicode_pp",
                "test_electrum_pp",
                "test_electrum_unicode_pp",
                "test_electrum2_pp",
                "test_electrum2_unicode_pp",
                "test_blockchain_v0_pp",
                "test_blockchain_v0_unicode_pp",
                "test_blockchain_secondpass_pp",
                "test_blockchain_secondpass_unicode_pp",
                "test_blockchain_secondpass_no_iter_count_pp",
                "test_invalid_crc")),
            module=sys.modules[__name__]
        ))
        self.addTests(tl.loadTestsFromTestCase(Test08BIP39Passwords))


if __name__ == '__main__':

    import argparse

    # Add two new arguments to those already provided by unittest.main()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--utf8",      action="store_true")
    parser.add_argument("--no-buffer", action="store_true")
    args, unittest_args = parser.parse_known_args()
    sys.argv[1:] = unittest_args

    tstr = unicode if args.utf8 else str

    unittest.main(buffer = not args.no_buffer)
