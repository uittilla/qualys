"""
Interface with requests
"""

import os
import sys

import xmltodict
import datetime as DT

class Fetch():

    def __init__(self, config, rest, exceptions):
        """
        FETCH
        :param config:
        """
        self.config = config
        self.rest = rest
        self.exception = exceptions


    def get_cve(self, cve):
        """
        Get NVD CVE information
        :return:
        """
        return cve.run()


    def get_qkb(self, qkb):
        """
        Get Qualys Knowledge base
        :return:
        """
        return qkb.run()


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

        with self.rest.get_session().request("POST",
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

            if r.status_code != 200:
                raise self.exception.QualysApiException(r.status_code, r.text)

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

    def clean_up(self):
        os.remove(self.config.asset_report_file)
        os.remove(self.config.knowledge_base_report_file)
