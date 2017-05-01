import os
import logging

from integralutils.BaseLoader import *
from integralutils import BaseSandboxParser
from integralutils import SpenderCuckooParser
from integralutils import CuckooParser
from integralutils import VxstreamParser
from integralutils import WildfireParser
from integralutils import EmailParser
from integralutils import Indicator

class BaseAlert(BaseLoader):
    def __init__(self, config_path=None):
        # Run the super init to inherit attributes and load the config.
        super().__init__(config_path=config_path)

        self.logger = logging.getLogger()        

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

    def __getstate__(self):
        d = dict(self.__dict__)
        if "logger" in d:
            del d["logger"]
        return d

    def __setstate__(self, d):
        self.__dict__.update(d)
                
    def add_sandbox(self, json_path):
        if isinstance(json_path, str):
            if os.path.exists(json_path):
                try:
                    sandbox_name = BaseSandboxParser.detect_sandbox(json_path)
                except Exception:
                    self.logger.exception("Error detecting sandbox: " + json_path)
                    raise

                sandbox_report = None
                if sandbox_name == "spendercuckoo":
                    try:
                        sandbox_report = SpenderCuckooParser.SpenderCuckooParser(json_path, config_path=self.config_path)
                        self.logger.debug("Parsed Spender Cuckoo report: " + json_path)
                    except Exception:
                        self.logger.exception("Error parsing Spender Cuckoo report: " + json_path)
                        raise

                elif sandbox_name == "cuckoo":
                    try:
                        sandbox_report = CuckooParser.CuckooParser(json_path, config_path=self.config_path)
                        self.logger.debug("Parsed Cuckoo report: " + json_path)
                    except Exception:
                        self.logger.exception("Error parsing Cuckoo report: " + json_path)
                        raise

                elif sandbox_name == "vxstream":
                    try:
                        sandbox_report = VxstreamParser.VxstreamParser(json_path, config_path=self.config_path)
                        self.logger.debug("Parsed VxStream report: " + json_path)
                    except Exception:
                        self.logger.exception("Error parsing VxStream report: " + json_path)
                        raise

                elif sandbox_name == "wildfire":
                    try:
                        sandbox_report = WildfireParser.WildfireParser(json_path, config_path=self.config_path)
                        self.logger.debug("Parsed Wildfire report: " + json_path)
                    except Exception:
                        self.logger.exception("Error parsing Wildfire report: " + json_path)
                        raise
                
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
