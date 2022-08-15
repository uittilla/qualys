import sqlite3
import json

class SqlLite():
    sql_queries = {
        "all":       "SELECT * FROM QualysKB LIMIT 1",
        "qualys_kb": "SELECT Hash FROM QualysKB WHERE id=?",
        "cve":       "SELECT Vector FROM CveVectors WHERE Id=?",
        "cwe":       "SELECT Cwe FROM CveVectors WHERE Id=?"
    }

    def __init__(self, db, config):
        sqlite3.register_adapter(dict, lambda d: json.dumps(d).encode('utf8'))
        sqlite3.register_converter("dictionary", lambda d: json.loads(d.decode('utf8')))

        self.sqliteConnection = sqlite3.connect(db)
        self.cursor = self.sqliteConnection.cursor()
        self.config = config

    def close(self):
        self.sqliteConnection.close()

    def query(self, query, key):
        self.cursor.execute(query, (key,))
        return self.cursor.fetchone()

    def save_many(self, caller):
        sql = self.config.insert_into_qualys_knowledge_base
        cursor = self.sqliteConnection.cursor()
        cursor.executemany(sql, caller.generator())
        self.sqliteConnection.commit()
        cursor.close()

    def create_db(self, sql):
        """
        handles database creation
        @return:
        """
        cursor = self.sqliteConnection.cursor()
        if self.config.verbose:
            print("Successfully Connected to SQLite")
        cursor.execute(sql)
        self.sqliteConnection.commit()
        if self.config.verbose:
            print("SQLite table created")

        cursor.close()

    def save_to_db(self, sql, key, value, entry):
        """
        Saves the entry yo the CveVectors table
        @param key:
        @param value:
        @param entry:
        @return:
        """
        try:
            cursor = self.sqliteConnection.cursor()
            cursor.execute(sql, (key, value, entry))
            self.sqliteConnection.commit()
            cursor.close()

        except sqlite3.Error as error:
            if self.config.verbose:
                print("Error while writing to sqlite", error)
