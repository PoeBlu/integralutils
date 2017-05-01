import os
import logging
import configparser
import json
import requests
from bs4 import BeautifulSoup

from integralutils.BaseLoader import *

class ConfluenceConnector(BaseLoader):
    def __init__(self, api_url=None, space_key=None, config_path=None):
        # Run the super init to inherit attributes and load the config.
        super().__init__(config_path=config_path)
            
        # Check if we want debugging.
        if "debug" in self.config["ConfluenceConnector"]:
            if self.config["ConfluenceConnector"]["debug"].lower() == "true":
                self.logger.debug("Setting debug status for ConfluenceConnector.")
                self.debug = True
            else:
                self.debug = False
        else:
            self.debug = False

        # Load the API URL from the config if we need to.
        if not api_url:
            self.api_url = self.config["ConfluenceConnector"]["api_url"]
        else:
            self.api_url = api_url
        
        # Load the space key from the config if we need to.
        if not space_key:
            self.space_key = self.config["ConfluenceConnector"]["space_key"]
        else:
            self.space_key = space_key
        
        # Load the login credentials.
        credential_file = self.config["ConfluenceConnector"]["credentials"]
        
        if "~" in credential_file:
            home_directory = os.path.expanduser("~")
            credential_file = credential_file.replace("~", home_directory)

        if not os.path.isfile(credential_file):
            raise FileNotFoundError('You do not have your Confluence credentials saved at: ' + credential_file)
        else:
            # Verify the creds file has the proper permissions.
            perms = oct(os.stat(credential_file).st_mode & 0o777)
            if perms == "0o600":
                with open(credential_file) as c:
                    self.username = c.readline().strip()
                    self.password = c.readline().strip()
            else:
                raise PermissionError("Your Confluence credentials file should have 600 permissions!")

    def __getstate__(self):
        d = dict(self.__dict__)
        if "logger" in d:
            del d["logger"]
        return d

    def __setstate__(self, d):
        self.__dict__.update(d)

    def _validate_request(self, request, error_msg='There was an error with the query.'):
        if request.status_code == 200:
            return True
        else:
            if self.debug:
                self.logger.error(request.text)
            raise ValueError(error_msg)

