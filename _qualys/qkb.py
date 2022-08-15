"""
Parse QKB and save to SQLITE3
"""
from _qualys import sqllite
from _qualys import rest
import datetime as DT
import os
import xmltodict

class Qkb():

    def __init__(self, config):
        """
        @param config:
        @return:
        """
        self.config   = config
        self.database = self.config.sqlite3_file
        self.sql      = sqllite.SqlLite(self.database, config)
        self.rest     = rest.Rest(self.config,
                              self.config.qualys_user['user'],
                              self.config.qualys_user['pass'],
                              use_auth=True)
        self.qkb_db = {}

        if config.verbose:
            print("  *** Fetcing QKB")


    def generator(self):
        """
        Generates qkb items
        :return:
        """
        for item in self.qkb_db :
            yield  (item, self.qkb_db[item])


    def run(self):
        """
        Bind all the moving parts here
        :return:
        """
        self.get_xml()
        self.parse_xml()
        self.sql.create_db(self.config.create_qualys_knowledge_base_db)
        self.sql.save_many(self)
        self.sql.close()

        #os.remove(f"{self.config.data_path}qkb.xml")
        #os.remove(self.config.shelve_db)


    def get_xml(self):
        """
        Downloads the qualys knowledge base XML file (big file)
        URL accepts param &last_modified_after=(date seven days ago) for quicker parsing
        :param use_proxy:
        :return:
        """
        if os.path.isfile(f"{self.config.data_path}qkb.xml"):
            print("*** File qkb.xml exists, skipping")
            return

        today = DT.date.today()
        week_ago = today - DT.timedelta(days=7)
        query = "action=list&details=All&last_modified_after={}".format(week_ago)

        if self.config.fullrun:
            query = "action=list&details=All"

        if self.config.verbose:
            print("Fetching", "?".join((self.config.qualys_links['knowledge_base'], query)))

        response = self.rest.get("?".join((self.config.qualys_links['knowledge_base'], query)),
                                {"X-Requested-With": "Python"})

        with open(f"{self.config.data_path}qkb.xml", 'wb') as file:
            file.write(response.content)


    def transform_item(self, _, kb_item):
        """
        xmltodict callback method
        :param _:
        :param kb_item:
        :return:
        """
        self.qkb_db[ kb_item['QID'] ] = kb_item
        return True


    def parse_xml(self):
        """
        Ingests the XML File and created individual knowledge based entries
        @Key: QID
        @return:
        """
        with open(f"{self.config.data_path}qkb.xml", "r") as f:
            xmltodict.parse(f.read(), item_depth=4, item_callback=self.transform_item)

        if self.config.verbose:
            print("*** Total QKB items", len(self.qkb_db) )