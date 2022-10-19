import pytest

from _qualys import config
from _qualys import cvss2
from _qualys import sqllite
from _qualys import rest
from _qualys import qkb
from _qualys import cve
from _qualys import fetch

confd = config.Config('/Users/mark.ibbotson/Dev/sec/qualys', 'qualys.yml')

@pytest.fixture
def mock_QualysConfig():
    class QualysConfig():
        def __init__(self):
            self.conf = confd

        def get_data_path(self):
            return self.conf.data_path

        def get_app_banner(self):
            return self.conf.app_banner
    return QualysConfig

@pytest.fixture
def mock_Qualys_Cvss2():
    class Qualys_Cvss2():
        def __init__(self):
            self.cvss2 = cvss2.Cvss2(confd)

        def convert_cvss2(self, cvss2):
            return self.cvss2.convert_cvss2(cvss2)
    return Qualys_Cvss2

@pytest.fixture
def mock_Qualys_KB():
    class Qualys_KB():
        def __init__(self):
            self.qkb = qkb.Qkb(confd, sqllite, rest)

        def get_qkb_entry(self):
            self.qkb.parse_xml()
            return self.qkb.qkb_db
    return Qualys_KB

@pytest.fixture
def mock_Qualys_Hosts():
    class Qualys_Host():
        def __init__(self):
            self.fetch = fetch.Fetch(confd, cve, qkb, rest)

        def get_host_entries(self):
            return self.fetch.host_detection_report_to_dict()
    return Qualys_Host