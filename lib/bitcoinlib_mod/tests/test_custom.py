# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    Unit Tests Custom classes
#    © 2018 February - 1200 Web Development <http://1200wd.com/>
#


import datetime


class CustomAssertions:

    def assertDictEqualExt(self, result_dict, expected_dict, none_allowed=None):
        """
        Compare dictionaries, skip items not found in expected dictionary.

        Lists and recursion's in dictionaries are allowed.

        :param result_dict: First dictionary with results
        :type result_dict: dict
        :param expected_dict: Second dictionary with expected values
        :type expected_dict: dict
        :param none_allowed: List of fields for which None value in result_dict is allowed
        :type none_allowed: list

        :return bool: Dictionaries are identical?
        """
        if none_allowed is None:
            none_allowed = []
        if not isinstance(expected_dict, dict):
            if expected_dict == result_dict:
                return True
            else:
                raise AssertionError("Different value for %s != %s" % (result_dict, expected_dict))
        expected_keys = expected_dict.keys()
        for k in result_dict:
            if k not in expected_keys:
                continue
            if isinstance(result_dict[k], dict):
                self.assertDictEqualExt(result_dict[k], expected_dict[k], none_allowed)
            elif isinstance(result_dict[k], list):
                for i in range(len(result_dict[k])):
                    if not isinstance(expected_dict[k], list):
                        raise AssertionError("No list expected for %s attribute, expected '%s' but received: '%s'" %
                                             (k, expected_dict[k], result_dict[k]))
                    self.assertDictEqualExt(result_dict[k][i], expected_dict[k][i], none_allowed)
            elif result_dict[k] != expected_dict[k]:
                if isinstance(result_dict[k], datetime.datetime):
                    if result_dict[k].date() == expected_dict[k].date():
                        continue
                if result_dict[k] is not None or k not in none_allowed:
                    raise AssertionError("Different value for '%s': %s != %s" % (k, result_dict[k], expected_dict[k]))
