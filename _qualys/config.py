import yaml

class Config():
    def __init__(self, path, yaml):
        """
        Extendable config
        @param path: yml file path
        @param yaml: yml config file
        """
        self.config =  self.read_config_file("/".join([path, yaml]))
        self.path = path

    def read_config_file(self, yaml_file):
        config = {}
        with open(yaml_file) as file:
            try:
                config = yaml.safe_load(file)
            except yaml.YAMLError as exc:
                print(exc)

        return config

    @property
    def data_path(self):
        return self.path + "/data/"

    @property
    def log_path(self):
        return self.data_path + "qualys.log"

    @property
    def asset_report_file(self):
        return self.data_path + "host_assets.xml"

    @property
    def knowledge_base_report_file(self):
        return self.data_path + "qualys_knowledge_base.xml"

    @property
    def sqlite3_file(self):
        return self.data_path + "SQLite_Qualys.db"

    @property
    def shelve_db(self):
        return self.data_path + "shelve_db"

    @property
    def app_banner(self):
        return self.config['app_banner']

    @property
    def host_detection_link(self):
        return self.config['qualys_links']['host_detection']

    @property
    def targets(self):
        return self.config['targets']

    @property
    def qualys_user(self):
        return self.config['qualys_user']

    @property
    def qualys_links(self):
        return self.config['qualys_links']

    @property
    def nvd(self):
        return self.config['nvd']

    @property
    def proxies(self):
        return self.config['proxies']

    @property
    def verbose(self):
        return self.config['verbose']

    @verbose.setter
    def verbose(self, value):
        self.config['verbose'] = value

    @property
    def fullrun(self):
        return self.config['fullrun']

    @fullrun.setter
    def fullrun(self, value):
        self.config['fullrun'] = value

    @property
    def create_cve_vectors_db(self):
        return self.config['sql_queries']['create_cve_vectors_db']

    @property
    def insert_into_cve_vectors(self):
        return self.config['sql_queries']['insert_into_cve_vectors']

    @property
    def create_qualys_knowledge_base_db(self):
        return self.config['sql_queries']['create_qualys_knowledge_base_db']

    @property
    def insert_into_qualys_knowledge_base(self):
        return self.config['sql_queries']['insert_into_qualys_knowledge_base']

    @property
    def query_all_qualys(self):
        return self.config['sql_queries']['query_all_qualys']

    @property
    def query_cve_vectors(self):
        return self.config['sql_queries']['query_nvd_cve']

    @property
    def cvss2_pattern(self):
        return self.config['cvss2_pattern']

    @property
    def cvss3_pattern(self):
        return self.config['cvss3_pattern']

    @property
    def cvss3_tag(self):
        return self.config['cvss3_tag']

    @property
    def query_nvd_cve(self):
        return self.config['sql_queries']['query_nvd_cve']

    @property
    def query_nvd_cwe(self):
        return self.config['sql_queries']['query_nvd_cwe']

    @property
    def qualys_assets(self):
        return self.config['qualys_assets']

    @property
    def use_proxy(self):
        return self.config['use_proxy']