"""
Import NVD CVE's and store in sqllite3
"""
from _qualys import sqllite
from _qualys import rest
import json
import gzip
import shutil
import os

class Cve():

    def __init__(self, config, sqllite, rest, exceptions):
        """
        Main entry
        @param config:
        @return:
        """
        self.config = config
        self.sql = sqllite.SqlLite(config.sqlite3_file, config)
        self.rest = rest
        self.exceptions = exceptions

        if config.verbose:
            print("   *** Fetching NVD")

        self.sql.create_db(self.config.create_cve_vectors_db)


    def run(self):
        """
        Gets the list of nvd files needed
        :return:
        """
        if self.config.verbose:
            print("Gets the list of nvd files")

        files = self.config.nvd["short_files"]

        if self.config.fullrun:
            files = self.config.nvd["all_files"]

        for file in files:
            self.worker(file)


    def worker(self, file):
        """
        @param file:
        @return:
        """
        if self.config.verbose:
            print("     --| Fetching", self.config.nvd["url"].format(file))

        response = self.rest.get(self.config.nvd["url"].format(file), {"X-Requested-With": "Python"})
        if response.status_code != 200:
            raise self.exception.NVDApiException(response.status_code, response.text)

        self.save_file(f"{self.config.data_path}{file}", response)
        self.unarchive(f"{self.config.data_path}{file}")
        self.parse_json(self.get_json(f"{self.config.data_path}{file}"))

        os.remove(f"{self.config.data_path}{file}")
        os.remove(f"{self.config.data_path}{file}.gz")


    def save_file(self, file, response):
        """
        Saves the files listed above to disk
        @param file:
        @param response:
        @return:
        """
        f = "{}.gz"
        with open(f.format(file), 'wb') as myfile:
            myfile.write(response.content)


    def unarchive(self, file):
        """
        Extract the files from gz to plain text/json
        @param file:
        @return:
        """
        lfile = "{}.gz"
        with gzip.open(lfile.format(file), 'r') as file_in, open(file, 'wb') as file_out:
            shutil.copyfileobj(file_in, file_out)


    def get_json(self, file):
        """
        Loads json file for parsing
        @param file:
        @return:
        """
        content = open(file, 'r')
        return json.loads(content.read())


    def parse_json(self, obj):
        """
        Parses JSON and build a dict
        Proceeds to save the entry to SqlLite
        @param obj:
        @return:
        """
        for key in obj['CVE_Items']:
            entry = ''
            if 'baseMetricV3' in key['impact']:
                id    = key['cve']['CVE_data_meta']['ID']
                value = key['impact']['baseMetricV3']['cvssV3']['vectorString']
                cwe   = key['cve']['problemtype']['problemtype_data'][0]

                if len(cwe['description']):
                    entry = cwe['description'][0]['value']

                self.sql.save_to_db(self.config.insert_into_cve_vectors, id, value, entry)