"""
Interface with requests
"""

import os
import sys

import xmltodict
import datetime as DT

from _qualys import cve
from _qualys import qkb
from _qualys import rest

class Fetch():

    def __init__(self, config):
        """
        FETCH
        :param config:
        """
        self.config = config
        self.rest = rest.Rest(self.config,
                              self.config.qualys_user['user'],
                              self.config.qualys_user['pass'],
                              use_auth=True)

        """ Remain upo to date or fail at matching information """
        try:
            self.get_cve()
            self.get_qkb()
        except:
            sys.exit("An error has occured while staying up to date")

    def get_cve(self):
        """
        Get NVD CVE information
        :return:
        """
        return cve.Cve(self.config).run()

    def get_qkb(self):
        """
        Get Qualys Knowledge base
        :return:
        """
        return qkb.Qkb(self.config).run()

    def get_host_detection_report(self):
        """
        Fetches the Qualys host detection report
        This is a basic fetch and can be refined
        :return:
        """
        today = DT.date.today()
        month = today - DT.timedelta(days=30)

        if os.path.isfile(self.config.asset_report_file):
            return

        if self.config.verbose:
            print("*** Fetching Qualys hosts detections")

        with self.rest._session.request("POST",
                 self.config.host_detection_link,
                 stream=True,
                 headers={"X-Requested-With": "Python"},
                 params={
                     'action':           'list',
                     'truncation_limit': 0,
                     'output_format':    'XML',
                     'status':           'Active,New,Fixed,Re-Opened',  # Optional
                     'detection_updated_since': month,
                     'max_days_since_last_vm_scan': 31,
                     'arf_kernel_filter': '0',
                     'show_results': 1,
                     'ag_titles': self.config.qualys_assets
                 }
            ) as r:

            with open(self.config.asset_report_file, "wb") as f:
                for chunk in r.iter_content(chunk_size=20480):
                    f.write(chunk)


    def host_detection_report_to_dict(self):
        """
        xml to python dict
        :return:
        """
        with open(self.config.asset_report_file, "r") as f:
            detections = xmltodict.parse(f.read())

        return detections