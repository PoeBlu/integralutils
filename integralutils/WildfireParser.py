import os
import sys
import requests
import logging
import sys

# Make sure the current directory is in the
# path so that we can run this from anywhere.
this_dir = os.path.dirname(__file__)
if this_dir not in sys.path:
    sys.path.insert(0, this_dir)

from BaseSandboxParser import *

class WildfireParser(BaseSandboxParser):          
    def __init__(self, config, json_report_path, whitelister=None):
        # Run the super init to inherit attributes and load the config.
        super().__init__(config, json_report_path, whitelister=whitelister)

        # Try and load this report from cache.
        if not self.load_from_cache():
            # Read some items the config file.
            self.sandbox_display_name = self.config["WildfireParser"]["sandbox_display_name"]
            
            # Fail if we can't parse the MD5. This is used as a sanity check when
            # figuring out which of the sandbox parsers you should use on your JSON.
            self.md5 = self.parse(self.report, "wildfire", "file_info", "md5")
            if not self.md5:
                self.logger.critical("Unable to parse Wildfire MD5 from: " + str(json_report_path))
                return None
                
            self.logger.debug("Parsing Wildfire sample " + self.md5)
            
            # Most Wildfire values depend on this.
            self.reports_json = self.parse(self.report, "wildfire", "task_info", "report")
            
            # In case there was only a single report, make it a list anyway.
            if isinstance(self.reports_json, dict):
                self.reports_json = [self.reports_json]
            
            # Parse some basic info directly from the report.
            self.filename = "sample"
            self.sha1 = self.parse(self.report, "wildfire", "file_info", "sha1")
            self.sha256 = self.parse(self.report, "wildfire", "file_info", "sha256")
            
            # The rest of the info requires a bit more parsing.
            self.sandbox_url = self.parse_sandbox_url()
            self.contacted_hosts = self.parse_contacted_hosts()
            self.dropped_files = self.parse_dropped_files()
            self.http_requests = self.parse_http_requests()
            self.dns_requests = self.parse_dns_requests()
            self.process_tree = self.parse_process_tree()
            self.process_tree_urls = self.parse_process_tree_urls()
            self.mutexes = self.parse_mutexes()
            self.json_urls = self.parse_json_urls()
            self.all_urls = self.get_all_urls()
            
            # Extract the IOCs.
            self.extract_indicators()
            
            # Get rid of the JSON report to save space.
            self.report = None
    
            # Cache the report.
            self.save_to_cache()

    def __getstate__(self):
        d = dict(self.__dict__)
        if "logger" in d:
            del d["logger"]
        if "strings" in d:
            del d["strings"]
        if "whitelister" in d:
            del d["whitelister"]
        return d

    def __setstate__(self, d):
        self.__dict__.update(d)

    def parse_sandbox_url(self):
        if self.sha256:
            return "https://wildfire.paloaltonetworks.com/wildfire/reportlist?search=" + self.sha256
        else:
            return ""

    def parse_http_requests(self):
        self.logger.debug("Parsing HTTP requests")

        # We use a set instead of a list since there are multiple Wildfire reports.
        # This prevents any duplicate requests being returned.
        http_requests = set()
        
        # Loop over each Wildfire report (usually should be 2).
        for report in self.reports_json:
            try:
                requests = report["network"]["url"]
                
                if isinstance(requests, dict):
                    requests = [requests]
                    
                for request in requests:
                    r = HttpRequest()
                
                    try: r.host = request["@host"]
                    except KeyError: pass
                
                    try: r.uri = request["@uri"]
                    except KeyError: pass
                
                    try: r.method = request["@method"]
                    except KeyError: pass
                
                    try: r.user_agent = request["@user_agent"]
                    except KeyError: pass
                
                    http_requests.add(r)
            except KeyError:
                pass
            except TypeError:
                pass
        
        return list(http_requests)
    
    def parse_dns_requests(self):
        self.logger.debug("Parsing DNS requests")

        # We use a set instead of a list since there are multiple Wildfire reports.
        # This prevents any duplicate requests being returned.
        dns_requests = set()
        
        # Loop over each Wildfire report (usually should be 2).
        for report in self.reports_json:
            try:
                requests = report["network"]["dns"]
                
                if isinstance(requests, dict):
                    requests = [requests]
                    
                for request in requests:
                    r = DnsRequest()
                
                    try: r.request = request["@query"]
                    except KeyError: pass
                
                    try: r.type = request["@type"]
                    except KeyError: pass
                
                    try: r.answer = request["@response"]
                    except KeyError: pass
                
                    try: r.user_agent = request["@user_agent"]
                    except KeyError: pass
                
                    dns_requests.add(r)
            except KeyError:
                pass
            except TypeError:
                pass
        
        return list(dns_requests)

    def parse_dropped_files(self):
        self.logger.debug("Parsing dropped files")

        # We use a set instead of a list since there are multiple Wildfire reports.
        # This prevents any duplicate requests being returned.
        dropped_files = set()
        
        # Loop over each Wildfire report (usually should be 2).
        for report in self.reports_json:
            try:
                process_list = report["process_list"]["process"]
                
                if isinstance(process_list, dict):
                    process_list = [process_list]
                    
                for process in process_list:
                    try:
                        created_files = process["file"]["Create"]
                        
                        if isinstance(created_files, dict):
                            created_files = [created_files]
                            
                        for file in created_files:
                            d = DroppedFile()
                        
                            try: d.filename = file["@name"].split("\\")[-1]
                            except KeyError: pass
                        
                            try: d.type = file["@type"]
                            except KeyError: pass
                        
                            try: d.path = file["@name"]
                            except KeyError: pass
                        
                            try: d.size = file["@size"]
                            except KeyError: pass
                        
                            try: d.md5 = file["@md5"]
                            except KeyError: pass
                        
                            try: d.sha1 = file["@sha1"]
                            except KeyError: pass
                        
                            try: d.sha256 = file["@sha256"]
                            except KeyError: pass
                        
                            dropped_files.add(d)
                    except KeyError:
                        pass
                    except TypeError:
                        pass
            except KeyError:
                pass
            except TypeError:
                pass
        
        return list(dropped_files)
    
    def parse_contacted_hosts(self):
        self.logger.debug("Parsing contacted hosts")

        # We use a set instead of a list since there are multiple Wildfire reports.
        # This prevents any duplicate hosts being returned.
        contacted_hosts = set()
        
        # Loop over each Wildfire report (usually should be 2).
        for report in self.reports_json:
            try:
                hosts = report["network"]["TCP"]
                
                if isinstance(hosts, dict):
                    hosts = [hosts]
                    
                for host in hosts:
                    h = ContactedHost()
                
                    try: h.ipv4 = host["@ip"]
                    except KeyError: pass
                
                    try: h.port = host["@port"]
                    except KeyError: pass
                
                    try: h.protocol = "TCP"
                    except KeyError: pass
                
                    try: h.location = host["@country"]
                    except KeyError: pass
                
                    contacted_hosts.add(h)
            except KeyError:
                pass
            except TypeError:
                pass
            
            try:
                hosts = report["network"]["UDP"]
                
                if isinstance(hosts, dict):
                    hosts = [hosts]
                    
                for host in hosts:
                    h = ContactedHost()
                
                    try: h.ipv4 = host["@ip"]
                    except KeyError: pass
                
                    try: h.port = host["@port"]
                    except KeyError: pass
                
                    try: h.protocol = "UDP"
                    except KeyError: pass
                
                    try: h.location = host["@country"]
                    except KeyError: pass
                
                    contacted_hosts.add(h)
            except KeyError:
                pass
            except TypeError:
                pass
        
        return list(contacted_hosts)
    
    def parse_process_tree_urls(self):
        self.logger.debug("Looking for URLs in the process tree")
        return RegexHelpers.find_urls(str(self.parse_process_tree()))
    
    def parse_process_tree(self):
        self.logger.debug("Parsing process tree")

        def walk_tree(process_json=None, process_list=None, previous_pid=0):
            if not process_list:
                process_list = ProcessList()
            
            if isinstance(process_json, dict):
                process_json = [process_json]
                
            if process_json:
                for process in process_json:
                    command = process["@text"]
                    pid = process["@pid"]
                    parent_pid = previous_pid
                    new_process = Process(command, pid, parent_pid)
                    process_list.add_process(new_process)
                    try:
                        process_list = walk_tree(process["child"]["process"], process_list, pid)
                    except KeyError:
                        pass
                    except TypeError:
                        pass
                
            return process_list

        process_tree_to_use = None
        process_tree_to_use_size = 0
        for report in self.reports_json:
            try:
                process_tree = report["process_tree"]["process"]
                process_tree_size = sys.getsizeof(process_tree)
                if process_tree_size > process_tree_to_use_size:
                    process_tree_to_use = process_tree
                    process_tree_to_use_size = process_tree_size
            except KeyError:
                pass
            except TypeError:
                pass

        return walk_tree(process_json=process_tree_to_use)
    
    def parse_mutexes(self):
        self.logger.debug("Parsing mutexes")

        # We use a set instead of a list since there are multiple Wildfire reports.
        # This prevents any duplicate mutexes being returned.
        mutexes = set()
        
        # Loop over each Wildfire report (usually should be 2).
        for report in self.reports_json:
            try:
                process_list = report["process_list"]["process"]
                
                if isinstance(process_list, dict):
                    process_list = [process_list]
                    
                for process in process_list:
                    try:
                        mutexes_created = process["mutex"]["CreateMutex"]
                        
                        if isinstance(mutexes_created, dict):
                            mutexes_created = [mutexes_created]
                            
                        for mutex in mutexes_created:
                            if mutex["@name"] != "<NULL>":
                                mutexes.add(mutex["@name"])
                    except KeyError:
                        pass
                    except TypeError:
                        pass
            except KeyError:
                pass
            except TypeError:
                pass
        
        return sorted(list(mutexes))
