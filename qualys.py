#!/bin/env python3
"""
Ibbo was ere


"""
import os
import argparse
import random

from _qualys import exceptions
from _qualys import config
from _qualys import cve
from _qualys import qkb
from _qualys import rest
from _qualys import sqllite
from _qualys import cvss2
from _qualys import fetch
from _qualys import parse

def mixup(hash):
    """ Random order the dict """
    l = list(hash.items())
    random.shuffle(l)
    return dict(l)

def qualys(config, fetch, parse):
    if config.verbose:
        print("*** Fetching required sources and parsing")
    fetch.get_host_detection_report()

    if config.verbose:
        print("*** Combining data and extracting vulnerabilities")
    detections = fetch.host_detection_report_to_dict()
    hosts      = list(detections["HOST_LIST_VM_DETECTION_OUTPUT"]['RESPONSE']['HOST_LIST']['HOST'])
    container  = parse.extract_host_info(hosts)

    return mixup(container)

def arg_parse(config):
    parser = argparse.ArgumentParser(description=config.app_banner)

    group = parser.add_mutually_exclusive_group()
    group.add_argument ('-p',  '--publish',   action='store_true', help='Fetch qualys data and prepare it for consumption')
    parser.add_argument('-f', '--fullrun',    action='store_true', help='Enact a full qualys kb run')
    parser.add_argument('-a', '--all_hosts',  action='store_true', help='Merge all related vulns under one QID')
    parser.add_argument('-v', "--verbose",    action='store_true', help='Increase output verbosity')

    return parser.parse_args()

if __name__ == '__main__':
    file_path = os.path.realpath(__file__)
    path = os.path.abspath(os.path.join(file_path, os.pardir))
    conf = config.Config(path, 'qualys.yml')
    args = arg_parse(conf)

    if args.verbose:   conf.verbose = True
    if args.fullrun:   conf.fullrun = True
    if args.all_hosts: conf.all_hosts = True

    """ Instatiate the objects and Inject our dependencies """
    try:
        q_rest  = rest.Rest(conf, conf.qualys_user['user'], conf.qualys_user['pass'], exceptions, use_auth=True)
        q_cve   = cve.Cve(conf, sqllite, q_rest, exceptions)
        q_qkb   = qkb.Qkb(conf, sqllite, q_rest, exceptions)
        q_cvs2  = cvss2.Cvss2(conf)
        q_fetch = fetch.Fetch(conf, q_rest, exceptions)

        """ Remain upo to date or fail at matching information """
        q_fetch.get_cve(q_cve)
        q_fetch.get_qkb(q_qkb)

        q_parse = parse.Parse(conf, sqllite, q_cvs2)

        if conf.verbose:
            print("*** Its ready")
        for id, vuln in qualys(conf, q_fetch, q_parse).items():
            print(id, vuln)

        #q_fetch.clean_up()

    except exceptions.QualysApiException as e:
        print('Got an error talking to the Qualys API:')
        for line in e.message:
            print(line, end='')
    except exceptions.NVDApiException as e:
        print('Got an error talking to the NVD API:')
        for line in e.message:
            print(line, end='')