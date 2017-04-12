import json

from integralutils.BaseAlert import *

class ACEAlert(BaseAlert):
    def __init__(self, alert_path, config_path=None):
        # Run the super init to inherit attributes and load the config.
        super().__init__(config_path=config_path)
        
        alert_json_path = os.path.join(alert_path, "data.json")
        alert_json_path = os.path.normpath(alert_json_path)
        
        with open(alert_json_path) as a:
            self.json = json.load(a)
            
        self.iocs = []
        self.source = ""
        self.path = alert_path
        self.time = self.json["event_time"]
        self.tool = self.json["tool"]
        self.type = self.json["type"]
        self.name = self.json["uuid"]
        self.description = self.json["description"]
        self.company = self.json["company_name"]
        
        # Load the URL from the config file.
        self.alert_url = self.config["ACEAlert"]["alert_url"] + self.name

        ##################
        ##              ##
        ##  FIND EMAIL  ##
        ##              ##
        ##################        
        # Get a listing of the alert directory to try and find an e-mail.
        alert_files = os.listdir(self.path)
        potential_emails = []
        for file in alert_files:
            file_path = os.path.join(self.path, file)
            if os.path.isfile(file_path):
                mime = self.get_file_mimetype(os.path.join(self.path, file))
                if "rfc822" in mime:
                    email = EmailParser.EmailParser(smtp_path=file_path)
                    email.reference = self.alert_url
                    potential_emails.append(email)
                    
        # Since ACE makes .header files that also appear as rfc822 files, pick the right one.
        if len(potential_emails) == 1:
            self.email = potential_emails[0]
            
        elif len(potential_emails) > 1:
            self.email = next(email for email in potential_emails if email.body or email.html)
        
        #####################
        ##                 ##
        ##  USER ANALYSIS  ##
        ##                 ##
        #####################
        # Try and find any user analysis files.
        user_analysis_files = self.get_all_analysis_paths("saq.modules.user:EmailAddressAnalysis")
        
        # Parse any user_analysis_files.
        self.user_analysis = []
        for file in user_analysis_files:
            if os.path.exists(os.path.join(self.path, ".ace", file)):
                with open(os.path.join(self.path, ".ace", file)) as j:
                    json_data = json.load(j)
                    
                    # Verify that certain keys actually have values.
                    if "cn" not in json_data: json_data["cn"] = ""
                    if "displayName" not in json_data: json_data["displayName"] = ""
                    if "mail" not in json_data: json_data["mail"] = ""
                    if "title" not in json_data: json_data["title"] = ""
                    if "description" not in json_data: json_data["description"] = [""]
                    if "department" not in json_data: json_data["department"] = ""
                    if "company" not in json_data: json_data["company"] = ""
                    if "distinguishedName" not in json_data: json_data["distinguishedName"] = ""
                    self.user_analysis.append(json_data)

        ############
        ##        ##
        ##  URLS  ##
        ##        ##
        ############
        # Save whatever URLs ACE was able to automatically extract.
        self.urls = set()
        
        url_files = self.get_all_analysis_paths("saq.modules.file_analysis:URLExtractionAnalysis")
        for file in url_files:
            with open(os.path.join(self.path, ".ace", file)) as j:
                json_data = json.load(j)
                for url in json_data:
                    if url.endswith("/"):
                        url = url[:-1]
                    self.urls.add(url)
                    
        # Try and remove any URLs that look like partial versions of other URLs.
        unique_urls = set()
        for url in self.urls:
            if not any(other_url.startswith(url) and other_url != url for other_url in self.urls):
                unique_urls.add(url)
        self.urls = sorted(list(unique_urls))
                    
        # Make Indicators for any URLs that ACE extracted.
        indicator_list = Indicator.generate_url_indicators(self.urls)
        
        # Add some additional tags and add them to our main IOC list.
        for ind in indicator_list:
            ind.add_tags("ace_extracted_url")
            self.iocs.append(ind)

        ###########################
        ##                       ##
        ##  FIND SANDBOX REPORT  ##
        ##                       ##
        ###########################
        valid_sandbox_paths = ["cuckoo", "vxstream", "wildfire"]

        # Walk the entire alert directory to find any possible sandbox reports.
        for root, dirs, files in os.walk(self.path):
            for file in files:
                # Make sure we are in a valid sandbox directory.
                if any(path in root for path in valid_sandbox_paths):
                    # Make sure the file ends with .json.
                    if file.endswith(".json"):
                        # Filter out the "network_" and "processtree_" WildFire JSON.
                        if not root.endswith("dropped") and "network_" not in file and "processtree_" not in file:
                            # At this point, assume this is a sandbox report. Try to add it.
                            sandbox_json_path = os.path.join(root, file)
                            self.add_sandbox(sandbox_json_path)

    def get_all_analysis_paths(self, ace_module):
        analysis_paths = []

        # Loop over each observable in the alert.
        for observable in self.json["observable_store"].keys():
            # See if there is an analysis for the given ACE module.
            try:
                json_file = self.json["observable_store"][observable]["analysis"][ace_module]["details"]["file_path"]
                if json_file:
                    analysis_paths.append(self.json["observable_store"][observable]["analysis"][ace_module]["details"]["file_path"])
            except KeyError:
                pass

        return analysis_paths
