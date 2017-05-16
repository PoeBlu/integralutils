from bs4 import BeautifulSoup
import json
import logging
import os
import requests
import sys

# Make sure the current directory is in the
# path so that we can run this from anywhere.
this_dir = os.path.dirname(__file__)
if this_dir not in sys.path:
    sys.path.insert(0, this_dir)

class ConfluenceConnector():
    def __init__(self, config, whitelister=None):
        # Initiate logging.
        self.logger = logging.getLogger()

        # Save the config. This should be a ConfigParser object.
        self.config = config

        # Save the whitelister. This should be a Whitelist object.
        self.whitelister = whitelister
           
        # Check if we are verifying requests.
        if self.config["Requests"]["verify"].lower() == "true":
            self.requests_verify = True
        
            # Now check if we want to use a custom CA cert to do so.
            if "ca_cert" in self.config["Requests"]:
                self.requests_verify = self.config["Requests"]["ca_cert"]
        else:
            self.requests_verify = False

        # Load the API URL from the config if we need to.
        self.api_url = self.config["ConfluenceConnector"]["api_url"]
        
        # Load the space key from the config if we need to.
        self.space_key = self.config["ConfluenceConnector"]["space_key"]
        
        # Load the login credentials.
        credential_file = self.config["ConfluenceConnector"]["credentials"]
        
        if "~" in credential_file:
            home_directory = os.path.expanduser("~")
            credential_file = credential_file.replace("~", home_directory)

        if not os.path.isfile(credential_file):
            self.logger.critical("You do not have your Confluence credentials saved at: " + credential_file)
            raise FileNotFoundError("You do not have your Confluence credentials saved at: " + credential_file)
        else:
            # Verify the creds file has the proper permissions.
            perms = oct(os.stat(credential_file).st_mode & 0o777)

            with open(credential_file) as c:
                self.username = c.readline().strip()
                self.password = c.readline().strip()

            if not perms == "0o600":
               self.logger.critical("Your Confluence credentials file should have 600 permissions!")

    # Override __get/setstate__ in case someone
    # wants to pickle an object of this class.
    def __getstate__(self):
        d = dict(self.__dict__)
        if "logger" in d:
            del d["logger"]
        return d

    def __setstate__(self, d):
        self.__dict__.update(d)

    def _validate_request(self, request, error_msg="There was an error with the query."):
        if request.status_code == 200:
            return True
        else:
            self.logger.critical(error_msg)
            self.logger.critical(request.text)

