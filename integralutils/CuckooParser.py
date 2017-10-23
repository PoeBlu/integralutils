import os
import requests
import logging
import sys
import zipfile
import tempfile
import shutil
import base64
from urllib.parse import urlparse

# Make sure the current directory is in the
# path so that we can run this from anywhere.
this_dir = os.path.dirname(__file__)
if this_dir not in sys.path:
    sys.path.insert(0, this_dir)

from BaseSandboxParser import *

class CuckooParser(BaseSandboxParser):          
    def __init__(self, config, json_report_path, screenshot=True, whitelister=None):
        # Run the super init to inherit attributes and load the config.
        super().__init__(config, json_report_path, whitelister=whitelister)

        # Try and load this report from cache.
        if not self.load_from_cache():
            self.logger.info("Parsing Cuckoo sandbox report: " + json_report_path)
    
            # Read some items the config file.
            self.base_url = self.config["CuckooParser"]["base_url"]
            self.sandbox_display_name = self.config["CuckooParser"]["sandbox_display_name"]
    
            self.report_directory = os.path.dirname(json_report_path)
            
            # Fail if we can't parse the MD5. This is used as a sanity check when
            # figuring out which of the sandbox parsers you should use on your JSON.
            self.md5 = self.parse(self.report, "target", "file", "md5")
            if not self.md5:
                self.logger.critical("Unable to parse Cuckoo MD5 from: " + str(json_report_path))
                return None
                
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
            self.decoded_process_tree = self.decode_process_tree()
            self.process_tree_urls = self.parse_process_tree_urls()
            self.mutexes = self.parse_mutexes()
            self.resolved_apis = self.parse_resolved_apis()
            self.created_services = self.parse_created_services()
            self.started_services = self.parse_started_services()
            self.strings = self.parse_strings()
            #self.strings_urls = self.parse_strings_urls()
            self.strings_urls = []
            #self.json_urls = self.parse_json_urls()
            self.all_urls = self.get_all_urls()
            
            # Extract the IOCs.
            self.extract_indicators()
            
            # Get rid of the JSON report to save space.
            self.report = None
    
            # Cache the report.
            self.save_to_cache()

    # Override __get/setstate__ in case someone
    # wants to pickle an object of this class.
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
        return self.base_url + "/analysis/" + self.sample_id + "/"
    
    def download_screenshot(self):
        if self.screenshot_repository:
            screenshot_zip_path = os.path.join(self.screenshot_repository, self.md5 + "_cuckoo.zip")
            screenshot_path = os.path.join(self.screenshot_repository, self.md5 + "_cuckoo.jpg")

            # If the screenshot .jpg hasn't already been cached...
            if not os.path.exists(screenshot_path):

                # If the screenshot .zip hasn't already been cached...
                if not os.path.exists(screenshot_zip_path):

                    # This URL will download the .zip of all the screenshots.
                    url = self.parse_screenshot_url()
    
                    if url:
                        try:
                            request = requests.get(url, allow_redirects=True, verify=self.requests_verify)
                            self.logger.debug("Downloading screenshots .zip " + url)
    
                            if request.status_code == 200:
                                with open(screenshot_zip_path, "wb") as url_file:
                                    url_file.write(request.content)
    
                        except requests.exceptions.ConnectionError:
                            return None
                
                # The .zip is cached, but the screenshot is not. Extract the .zip
                # to get at the screenshots. Extract them to a temp dir and pick
                # the "best" screenshot from there to cache.
                with tempfile.TemporaryDirectory() as temp_dir:
                    with zipfile.ZipFile(screenshot_zip_path, "r") as zf:
                        zf.extractall(temp_dir)
                    
                    # Our VMs use a plain black Desktop background, so the logic
                    # is that the largest filesize of the screenshots is going
                    # to have the most "stuff" on it, so we'll pick that one.
                    best_screenshot = {"path": "", "size": 0}
                    for temp_screenshot in os.listdir(temp_dir):
                        temp_screenshot_path = os.path.join(temp_dir, temp_screenshot)
                        temp_screenshot_size = int(os.path.getsize(temp_screenshot_path))
                        if temp_screenshot_size > best_screenshot["size"]:
                            best_screenshot["path"] = temp_screenshot_path
                            best_screenshot["size"] = int(temp_screenshot_size)

                    # If we have a best screenshot, copy it out of the temp
                    # directory into the screenshot cache.
                    if best_screenshot["path"]:
                        self.logger.debug("Copying screenshot from temp dir to cache: {}".format(screenshot_path))
                        shutil.copy2(best_screenshot["path"], screenshot_path)
                        return screenshot_path
            else:
                return screenshot_path
        
        return None
        
    def parse_screenshot_url(self):
        return self.base_url + "/api/tasks/screenshots/" + str(self.sample_id)
   
    def parse_http_requests(self):
        self.logger.debug("Parsing HTTP requests")

        http_requests = []
        http_requests_json = self.parse(self.report, "network", "http")
        
        if http_requests_json:
            for request in http_requests_json:
                r = HttpRequest()

                try:
                    full_url = request["path"]
                    parsed_url = urlparse(full_url)
                    r.host = parsed_url.netloc
                    r.port = parsed_url.port
                    r.uri = parsed_url.path
                except:
                    pass
                
                #try: r.host = request["host"]
                #except KeyError: pass
            
                #try: r.port = request["port"]
                #except KeyError: pass
            
                #try: r.uri = request["path"]
                #except KeyError: pass
            
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
                    self.logger.debug("Adding dropped file: " + f.filename)
                    dropped_files.append(f)
                else:
                    self.logger.error("Unable to parse dropped filename: " + f.md5)

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
        urls = RegexHelpers.find_urls(str(self.parse_process_tree()))
        urls += RegexHelpers.find_urls(self.decode_process_tree())
        return urls

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

    def decode_process_tree(self):
        process_tree = str(self.parse_process_tree())
        decoded_process_tree = process_tree
        # Try to decode base64 chunks.
        for chunk in process_tree.split():
            try:
                decoded_chunk = base64.b64decode(chunk).decode('utf-8')
                if '\x00' in decoded_chunk:
                    decoded_chunk = base64.b64decode(chunk).decode('utf-16')
                decoded_process_tree = decoded_process_tree.replace(chunk, decoded_chunk)
            except:
                pass

        # Try to decode int arrays.
        try:
            int_array_regex = re.compile(r"\(((\s*\d+\s*,?)+)\)")
            matches = int_array_regex.findall(decoded_process_tree)
            for match in matches:
                orig_int_array = match[0]
                clean_int_array = ''.join(orig_int_array.split()).split(',')
                chars = ''.join([chr(int(num)) for num in clean_int_array])
                decoded_process_tree = decoded_process_tree.replace(orig_int_array, chars)
        except:
            pass

        # Try to decode split+int arrays.
        try:
            split_int_array_regex = re.compile(r"\(\s*'((\s*\d+.)+)\s*'")
            matches = split_int_array_regex.findall(decoded_process_tree)
            for match in matches:
                orig_int_array = match[0]
                int_regex = re.compile(r"\d+")
                int_array = int_regex.findall(orig_int_array)
                chars = ''.join([chr(int(num)) for num in int_array])
                decoded_process_tree = decoded_process_tree.replace(orig_int_array, chars)
        except:
            pass

        if decoded_process_tree != process_tree:
            return decoded_process_tree
        else:
            return ''

    def parse_mutexes(self):
        self.logger.debug("Parsing mutexes")

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
