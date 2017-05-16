import logging
import magic
import os
import sys

# Make sure the current directory is in the
# path so that we can run this from anywhere.
this_dir = os.path.dirname(__file__)
if this_dir not in sys.path:
    sys.path.insert(0, this_dir)

import BaseSandboxParser
import SpenderCuckooParser
import CuckooParser
import VxstreamParser
import WildfireParser

class BaseAlert():
    def __init__(self, config, whitelister=None):
        # Initiate logging.
        self.logger = logging.getLogger()

        # Save the config. This should be a ConfigParser object.
        self.config = config

        # Save the whitelister. This should be a Whitelist object.
        self.whitelister = whitelister

        # A list of Indicator objects for the alert.
        self.iocs = []
        
        # When did the alert happen?
        self.time = ""
        
        # What tool generated the alert?
        self.tool = ""
        
        # What kind of alert is this?
        self.type = ""
        
        # What is the alert's name?
        self.name = ""
        
        # What is alert's description?
        self.description = ""
        
        # Does the alert have a URL to view it?
        self.url = ""
        
        # EmailParser object if the alert was created in response to an e-mail.
        self.email = None
        
        # Any BaseSandboxParser results associated with the alert.
        # The structure is expected to be:
        # {"md5_of_sample": [BaseSandboxParser1, BaseSandboxParser2, BaseSandboxParser3]}
        self.sandbox = {}
        
        # Sort the sandbox reports by their URLs. This helps make sure they
        # are displayed in a consistent order for anything using them.
        for sample in self.sandbox:
            self.sandbox[sample].sort(key=lambda x: x.sandbox_url)

    # Override __get/setstate__ in case someone
    # wants to pickle an object of this class.
    def __getstate__(self):
        d = dict(self.__dict__)
        if "logger" in d:
            del d["logger"]
        return d

    def __setstate__(self, d):
        self.__dict__.update(d)

    def get_file_mimetype(self, file_path):
        if os.path.exists(file_path):
            return magic.from_file(file_path, mime=True)
        else:
            return ""
                
    def add_sandbox(self, json_path):
        if isinstance(json_path, str):
            if os.path.exists(json_path):
                try:
                    sandbox_name = BaseSandboxParser.detect_sandbox(json_path)
                except Exception:
                    # Log and skip this sandbox report if it couldn't be detected.
                    self.logger.exception("Error detecting sandbox: " + json_path)

                sandbox_report = None
                if sandbox_name == "spendercuckoo":
                    try:
                        sandbox_report = SpenderCuckooParser.SpenderCuckooParser(self.config, json_path, whitelister=self.whitelister)
                    except Exception:
                        # Log and skip this sandbox report if it couldn't be parsed.
                        self.logger.exception("Error parsing Spender Cuckoo report: " + json_path)

                elif sandbox_name == "cuckoo":
                    try:
                        sandbox_report = CuckooParser.CuckooParser(self.config, json_path, whitelister=self.whitelister)
                    except Exception:
                        # Log and skip this sandbox report if it couldn't be parsed.
                        self.logger.exception("Error parsing Cuckoo report: " + json_path)

                elif sandbox_name == "vxstream":
                    try:
                        sandbox_report = VxstreamParser.VxstreamParser(self.config, json_path, whitelister=self.whitelister)
                    except Exception:
                        # Log and skip this sandbox report if it couldn't be parsed.
                        self.logger.exception("Error parsing VxStream report: " + json_path)

                elif sandbox_name == "wildfire":
                    try:
                        sandbox_report = WildfireParser.WildfireParser(self.config, json_path, whitelister=self.whitelister)
                    except Exception:
                        # Log and skip this sandbox report if it couldn't be parsed.
                        self.logger.exception("Error parsing Wildfire report: " + json_path)
                
                # Continue if we successfully parsed a sandbox report.
                if sandbox_report:
                    # Check if this sample has already been added to the sandbox dictionary.
                    if sandbox_report.md5 in self.sandbox:
                        # Add the report if it isn't already there.
                        if not sandbox_report in self.sandbox[sandbox_report.md5]:
                            self.sandbox[sandbox_report.md5].append(sandbox_report)
                    # Since this is a new sample, set up a list for it.
                    else:
                        self.sandbox[sandbox_report.md5] = [sandbox_report]
