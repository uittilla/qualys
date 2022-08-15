"""
Converts cvss2 vectors into cvss3

"""

import re

class Cvss2():
    """
    Converts CVSS2 vector to CVSS3
    """

    def __init__(self, config):
        self.config = config

    def get_an_e(self, item, _e):
        value = item.split(":")

        if re.match("^ND", value[1]):
            _e += "X"
        elif re.match("^POC", value[1]):
            _e += "X"
        else:
            _e += value[1]

        return _e

    def get_the_rl(self, item, _rl):
        value = item.split(":")

        if re.match("^OF", value[1]):
            _rl += "O"
        elif re.match("^TF", value[1]):
            _rl += "T"
        elif re.match("^ND", value[1]):
            _rl += "X"
        else:
            _rl += value[1]

        return _rl

    def get_the_rc(self, item, _rc):
        value = item.split(":")
        if re.match("^UR", value[1]):
            _rc += "R"
        elif re.match("^UC", value[1]):
            _rc += "U"
        elif re.match("^ND", value[1]):
            _rc += "X"
        else:
            _rc += value[1]

        return _rc

    def get_the_av(self, item, _av):
        value = item.split(":")
        _av += value[1]

        return _av

    def get_the_ac(self, item, _ac):
        value = item.split(":")
        if re.match("^M", value[1]):
            _ac += "L"
        else:
            _ac += value[1]

        return _ac

    def get_the_c(self, item, _c):
        value = item.split(":")

        if re.match("^P", value[1]):
            _c += "L"
        elif re.match("^C", value[1]):
            _c += "L"
        else:
            _c += value[1]

        return _c

    def get_an_i(self, item, _i):
        value = item.split(":")

        if re.match("^P", value[1]):
            _i += "L"
        elif re.match("^C", value[1]):
            _i += "L"
        else:
            _i += value[1]

        return _i

    def get_an_a(self, item, _a):
        value = item.split(":")

        if re.match("^P", value[1]):
            _a += "L";
        elif re.match("^C", value[1]):
            _a += "L";
        else:
            _a += value[1]

        return _a

    def convert_cvss2(self, job):
        """
        Extract vector base and temporal.
        Convert to CVSS3 and combine
        :param job:
        :return: vector
        """

        job    = job.replace(self.config.cvss2_pattern, '')
        vector = job.split('E:')
        base   = vector[0]
        tmp    = "E:" + vector[1]

        cvss3 = "/".join((base, tmp))
        parts = cvss3.split("/")

        _e = "E:"
        _rl = "RL:"
        _rc = "RC:"
        _av = "AV:"
        _ac = "AC:"
        _au = "PR:N/UI:N/S:U"  # cvss3 has no Au: ... (use these defaults)
        _c = "C:"
        _i = "I:"
        _a = "A:"

        for item in parts:
            # Temporal
            if re.match("^E:", item):
                _e = self.get_an_e(item, _e)

            elif re.match("^RL:", item):
                _rl = self.get_the_rl(item, _rl)

            elif re.match("^RC:", item):
                _rc = self.get_the_rc(item, _rc)

            # Base
            elif re.match("^AV:", item):
                _av = self.get_the_av(item, _av)

            elif re.match("^AC:", item):
                _ac = self.get_the_ac(item, _ac)

            elif re.match("^C:", item):
                # not visible on transform page
                _c = self.get_the_c(item, _c)

            elif re.match("^I:", item):
                # not visible on transform page
                _i = self.get_an_i(item, _i)

            elif re.match("^A:", item):
                # not visible on transform page
                _a = self.get_an_a(item, _a)

        cvsstmp = "/".join((_e, _rl, _rc)).replace(")", "")
        cvssbase = "/".join((_av, _ac, _au, _c, _i, _a))

        if self.config.verbose:
            print("Transformed %s", "/".join((cvssbase, cvsstmp)))

        return "/".join((cvssbase, cvsstmp))
