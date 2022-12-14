"""

"""
import json
import requests

class Rest:
    def __init__(self, conf, user, password, exceptions, use_auth=True):
        """
        Constructor for generic net logic
        :param conf:
        :param user:
        :param password:
        :param use_auth:
        """
        self._session = requests.Session()
        self.config   = conf
        self.exception= exceptions

        if self.config.use_proxy:
            self._session.proxies = conf.proxies

        if use_auth:
            self._session.auth = (user, password)


    def get_session(self):
        return self._session

    def get(self, link, headers):
        """
        Default pass through no object parse
        @param link:
        @return:
        :param headers:
        """
        try:
            return self._session.get(link, headers=headers)
        except requests.ConnectionError as err:
            raise (err)


    def getty(self, link):
        """
        GET
        @param link:
        @return:
        """
        try:
            response = self._session.get(link)
            if response.status_code != 200:
                raise self.exception.QualysApiException(response.status_code, response.text)

            return response.json()
        except requests.ConnectionError as err:
            raise (err)


    def putty(self, link, data):
        """
        PUT
        @param link:
        @param data:
        @return:
        """
        try:
            response = self._session.put(link, json.dumps(data), headers={'content-type': 'application/json'})
            if response.status_code != 200:
                raise self.exception.QualysApiException(response.status_code, response.text)

            return response.json()
        except requests.ConnectionError as err:
            raise (err)


    def posty(self, link, data):
        """
        POST
        @param link:
        @param data:
        @return:
        """
        try:
            response = self._session.post(link, json.dumps(data), headers={'content-type': 'application/json'})
            if response.status_code != 201:
                raise self.exception.QualysApiException(response.status_code, response.text)

            return response.json()
        except requests.ConnectionError as err:
            raise (err)