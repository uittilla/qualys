#!/bin/env python3
"""
Ibbo was ere


"""

import os
import argparse
from _qualys import config
from _qualys import qualys

def arg_parse(config):
    parser = argparse.ArgumentParser(description=config.app_banner)

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p",  "--publish",   action='store_true', help="Fetch qualys data and prepare it for consumption")
    parser.add_argument('-f', '--fullrun',   action='store_true', help="Enact a full qualys kb run")
    parser.add_argument("-v", "--verbose",   action='store_true', help="Increase output verbosity")

    return parser.parse_args()

if __name__ == "__main__":
    file_path = os.path.realpath(__file__)
    path = os.path.abspath(os.path.join(file_path, os.pardir))
    config = config.Config(path, "qualys.yml")
    args = arg_parse(config)

    if args.verbose:
        config.verbose = True
    if args.fullrun:
        config.fullrun = True

    qualys.Qualys(config)
