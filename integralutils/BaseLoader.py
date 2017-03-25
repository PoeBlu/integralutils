import os
import magic
import configparser

class BaseLoader:
    def __init__(self, config_path=None):
        # If we weren't given a config_path, assume we're loading
        # the one shipped with integralutils.
        if not config_path:
            config_path = os.path.join(os.path.dirname(__file__), "etc", "config.ini")
            
        # Read the config.
        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self.config.read(config_path)
        
        # Check if we want to verify HTTPS requests.
        if self.config["Requests"]["verify"].lower() == "true":
            self.requests_verify = True
        
            # Now check if we want to use a custom CA cert to do so.
            if "ca_cert" in self.config["Requests"]:
                self.requests_verify = self.config["Requests"]["ca_cert"]
        else:
            self.requests_verify = False

    def get_file_mimetype(self, file_path):
        if os.path.exists(file_path):
            return magic.from_file(file_path, mime=True)
        else:
            return ""