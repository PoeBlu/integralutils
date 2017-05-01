import os
import requests
import configparser
import logging

from integralutils.BaseSandboxParser import *

class CuckooParser(BaseSandboxParser):          
    def __init__(self, json_report_path, screenshot=True, config_path=None):
        # Run the super init to inherit attributes and load the config.
        super().__init__(json_report_path, config_path=config_path)

        self.logger = logging.getLogger()
        self.logger.debug("Parsing Cuckoo report " + json_report_path)

        # Read some items the config file.
        self.base_url = self.config["CuckooParser"]["base_url"]
        self.sandbox_display_name = self.config["CuckooParser"]["sandbox_display_name"]

        self.report_directory = os.path.dirname(json_report_path)
        
        # Fail if we can't parse the MD5. This is used as a sanity check when
        # figuring out which of the sandbox parsers you should use on your JSON.
        self.md5 = self.parse(self.report, "target", "file", "md5")
        if not self.md5:
            raise ValueError("Unable to parse Cuckoo MD5 from: " + str(json_report_path))
        self.logger.debug("Parsing Cuckoo sample " + self.md5)
            
        # Parse some basic info directly from the report.
        self.sandbox_vm_name = self.parse(self.report, "info", "machine", "name")
        self.filename = self.parse(self.report, "target", "file", "name")
        self.sha1 = self.parse(self.report, "target", "file", "sha1")
        self.sha256 = self.parse(self.report, "target", "file", "sha256")
        self.sha512 = self.parse(self.report, "target", "file", "sha512")
        self.ssdeep = self.parse(self.report, "target", "file", "ssdeep")
        self.malware_family = self.parse(self.report, "malfamily")
        self.sample_id = str(self.parse(self.report, "info", "id"))
        
        # The rest of the info requires a bit more parsing.
        self.sandbox_url = self.parse_sandbox_url()
        if screenshot:
            self.screenshot_path = self.download_screenshot()
        self.contacted_hosts = self.parse_contacted_hosts()
        self.dropped_files = self.parse_dropped_files()
        self.http_requests = self.parse_http_requests()
        self.dns_requests = self.parse_dns_requests()
        self.process_tree = self.parse_process_tree()
        self.process_tree_urls = self.parse_process_tree_urls()
        self.mutexes = self.parse_mutexes()
        self.resolved_apis = self.parse_resolved_apis()
        self.created_services = self.parse_created_services()
        self.started_services = self.parse_started_services()
        self.strings = self.parse_strings()
        self.strings_urls = self.parse_strings_urls()
        self.all_urls = self.get_all_urls()
        
        # Extract the IOCs.
        self.extract_indicators()
        
        # Get rid of the JSON report to save space.
        self.report = None

    def __getstate__(self):
        d = dict(self.__dict__)
        if "logger" in d:
            del d["logger"]
        return d

    def __setstate__(self, d):
        self.__dict__.update(d)

    def parse_sandbox_url(self):
        return self.base_url + "/analysis/" + self.sample_id + "/"
    
    def download_screenshot(self):
        if self.screenshot_repository:
            screenshot_path = os.path.join(self.screenshot_repository, self.md5 + "_cuckoo.jpg")

            if not os.path.exists(screenshot_path):
                url = self.parse_screenshot_url()

                if url:
                    try:
                        request = requests.get(url, allow_redirects=True, verify=self.requests_verify)
                        self.logger.debug("Downloading screenshot " + url)

                        if request.status_code == 200:
                            with open(screenshot_path, "wb") as url_file:
                                url_file.write(request.content)

                            return screenshot_path
                    except requests.exceptions.ConnectionError:
                        return None
            else:
                return screenshot_path
        
        return None
        
    def parse_screenshot_url(self):
        # The Cuckoo JSON does not tell us how many screenshots are available,
        # so we must perform a HTTP HEAD request loop until we no longer receive
        # an image. After the loop is finished, we want to get the URL of the
        # largest image. Cuckoo uses a plain black background for the sandbox VM,
        # so the largest image should in theory have something interesting in it.
    
        # Start the HTTP HEAD loop with 0001
        image_int = 1
        image_number = str(image_int).zfill(4)
        url = self.base_url + "/file/screenshot/" + str(self.sample_id) + "/" + image_number + "/"

        # Keep a dictionary to store the image URLs and their size.
        screenshot_dict = {}
    
        try:
            self.logger.debug("Trying to identify best screenshot")

            # Perform the first HTTP HEAD request.
            req = requests.head(url, allow_redirects=True, verify=self.requests_verify)

            # Loop until we no longer receive an image.
            while req.headers["content-type"] == "image/jpeg":
                screenshot_dict[url] = int(req.headers["content-length"])
                image_int += 1
                image_number = str(image_int).zfill(4)
                url = self.base_url + "/file/screenshot/" + str(self.sample_id) + "/" + image_number + "/"
                req = requests.head(url, allow_redirects=True, verify=self.requests_verify)
        except requests.exceptions.ConnectionError:
            return ""
        
        # Sort the screenshot URLs by their size.
        screenshot_sorted = sorted(screenshot_dict, key=lambda k: screenshot_dict[k])
    
        if screenshot_sorted:
            # Set the URL to the last (largest) image.
            return screenshot_sorted[-1]
        else:
            return ""
            pass
    
    def parse_http_requests(self):
        self.logger.debug("Parsing HTTP requests")

        http_requests = []
        http_requests_json = self.parse(self.report, "network", "http")
        
        if http_requests_json:
            for request in http_requests_json:
                r = HttpRequest()
                
                try: r.host = request["host"]
                except KeyError: pass
            
                try: r.port = request["port"]
                except KeyError: pass
            
                try: r.uri = request["path"]
                except KeyError: pass
            
                try: r.method = request["method"]
                except KeyError: pass
            
                try: r.user_agent = request["user-agent"]
                except KeyError: pass
        
                # Only add the request if the host was successfully parsed.
                if r.host:
                    http_requests.append(r)
                    
        return http_requests
    
    def parse_dns_requests(self):
        self.logger.debug("Parsing DNS requests")

        dns_requests = []
        dns_requests_json = self.parse(self.report, "network", "dns")
        
        if dns_requests_json:
            for request in dns_requests_json:
                r = DnsRequest()
                
                try: r.request = request["request"]
                except KeyError: pass
            
                try: r.type = request["type"]
                except KeyError: pass
            
                # Technically, the Cuckoo JSON can have multiple answers listed,
                # but we are only going to grab the first one, as most of the time
                # there is only a single answer anyway.
                try: r.answer = request["answers"][0]["data"]
                except IndexError: pass
                except KeyError: pass
            
                try: r.answer_type = request["answers"][0]["type"]
                except IndexError: pass
                except KeyError: pass
        
                # Only add the request if the host was successfully parsed.
                if r.request:
                    dns_requests.append(r)
                    
        return dns_requests

    def parse_dropped_files(self):
        self.logger.debug("Parsing dropped files")
        dropped_files = []
        dropped_files_json = self.parse(self.report, "dropped")
                                                
        if dropped_files_json:
            for file in dropped_files_json:
                f = DroppedFile()
                
                try: f.filename = file["name"]
                except KeyError: pass

                try: f.path = file["guest_paths"][0]
                except KeyError: pass
            
                try: f.size = file["size"]
                except KeyError: pass
            
                try: f.type = file["type"]
                except KeyError: pass
            
                try: f.md5 = file["md5"]
                except KeyError: pass
            
                try: f.sha1 = file["sha1"]
                except KeyError: pass
            
                try:
                    f.sha256 = file["sha256"]
                    potential_path = os.path.join(self.report_directory, "dropped", f.sha256)
                    if os.path.exists(potential_path):
                        f.os_path = potential_path
                except KeyError: pass
            
                try: f.sha512 = file["sha512"]
                except KeyError: pass
            
                try: f.ssdeep = file["ssdeep"]
                except KeyError: pass
            
                # Only add the file if its filename was succesfully parsed.
                if f.filename:
                    dropped_files.append(f)

        return dropped_files
    
    def parse_contacted_hosts(self):
        self.logger.debug("Parsing contacted hosts")

        contacted_hosts = []
        contacted_hosts_json = self.parse(self.report, "network", "hosts")
        
        if contacted_hosts_json:
            for host in contacted_hosts_json:
                h = ContactedHost()

                h.ipv4 = host
                
                """ 
                try: h.ipv4 = host["ip"]
                except KeyError: pass
            
                try: h.location = host["country_name"]
                except KeyError: pass

                try:
                    if host["hostname"]:
                        h.add_associated_domain(host["hostname"])
                except KeyError: pass
                """
                
                # Only add the host if its IP was succesfully parsed.
                if h.ipv4:
                    contacted_hosts.append(h)
                
        return contacted_hosts
    
    def parse_process_tree_urls(self):
        self.logger.debug("Looking for URLs in process tree")
        return RegexHelpers.find_urls(str(self.parse_process_tree()))
    
    def parse_process_tree(self):
        self.logger.debug("Parsing process tree")

        def walk_tree(process_json=None, process_list=None):
            if not process_list:
                process_list = ProcessList()
            
            for process in process_json:
                #command = process["environ"]["CommandLine"]
                command = process["command_line"]
                pid = process["pid"]
                parent_pid = process["ppid"]
                new_process = Process(command, pid, parent_pid)
                process_list.add_process(new_process)
                process_list = walk_tree(process["children"], process_list)
                
            return process_list
                
        return walk_tree(process_json=self.parse(self.report, "behavior", "processtree"))

    def parse_mutexes(self):
        self.logger.debug("Parsing mutexe")

        mutexes = set()
        mutexes_json = self.parse(self.report, "behavior", "summary", "mutexes")
        
        if mutexes_json:
            for mutex in mutexes_json:
                mutexes.add(mutex)
                
        return sorted(list(mutexes))
    
    def parse_resolved_apis(self):
        self.logger.debug("Parsing resolved APIs")

        resolved_apis = set()
        resolved_apis_json = self.parse(self.report, "behavior", "summary", "resolved_apis")
        
        if resolved_apis_json:
            for api_call in resolved_apis_json:
                resolved_apis.add(api_call)
                
        return sorted(list(resolved_apis))
    
    def parse_created_services(self):
        self.logger.debug("Parsing created services")

        created_services = set()
        created_services_json = self.parse(self.report, "behavior", "summary", "created_services")
        
        if created_services_json:
            for service in created_services_json:
                created_services.add(service)
                
        return sorted(list(created_services))
    
    def parse_started_services(self):
        self.logger.debug("Parsing started services")

        started_services = set()
        started_services_json = self.parse(self.report, "behavior", "summary", "started_services")
        
        if started_services_json:
            for service in started_services_json:
                started_services.add(service)
                
        return sorted(list(started_services))
    
    def parse_strings_urls(self):
        self.logger.debug("Looking for URLs in strings")
        return RegexHelpers.find_urls(self.parse_strings())
    
    def parse_strings(self):
        self.logger.debug("Parsing strings")
        strings_json = self.parse(self.report, "strings")
        return "\n".join(strings_json)
