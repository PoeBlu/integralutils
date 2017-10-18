import os
import requests
import logging
import sys
import base64

# Make sure the current directory is in the
# path so that we can run this from anywhere.
this_dir = os.path.dirname(__file__)
if this_dir not in sys.path:
    sys.path.insert(0, this_dir)

from BaseSandboxParser import *

class VxstreamParser(BaseSandboxParser):          
    def __init__(self, config, json_report_path, screenshot=True, whitelister=None):
        # Run the super init to inherit attributes and load the config.
        super().__init__(config, json_report_path, whitelister=whitelister)

        # Try and load this report from cache.
        if not self.load_from_cache():
            # Read some items the config file.
            self.base_url = self.config["VxstreamParser"]["base_url"]
            self.sandbox_display_name = self.config["VxstreamParser"]["sandbox_display_name"]
    
            self.report_directory = os.path.dirname(json_report_path)
            
            # Fail if we can't parse the MD5. This is used as a sanity check when
            # figuring out which of the sandbox parsers you should use on your JSON.
            self.md5 = self.parse(self.report, "analysis", "general", "digests", "md5")
            if not self.md5:
                self.logger.critical("Unable to parse VxStream MD5 from: " + str(json_report_path))
                return None
                
            self.logger.debug("Parsing VxStream sample " + self.md5)
            
            # Parse some basic info directly from the report.
            self.filename = self.parse(self.report, "analysis", "general", "sample")
            self.sha1 = self.parse(self.report, "analysis", "general", "digests", "sha1")
            self.sha256 = self.parse(self.report, "analysis", "general", "digests", "sha256")
            self.sha512 = self.parse(self.report, "analysis", "general", "digests", "sha512")
            self.sample_id = str(self.parse(self.report, "analysis", "general", "controller", "environmentid"))
            self.sandbox_vm_name = self.parse(self.report, "analysis", "general", "controller", "client_name")
            
            # The rest of the info requires a bit more parsing.
            self.sandbox_url = self.parse_sandbox_url()
            if screenshot:
                # Try the "new" method of getting the screenshot first.
                # This means look for the .png screenshots inside the same
                # directory as this JSON report since it should be our
                # convention to use download them from the VxStream API when
                # we download the JSON report.
                self.screenshot_path = self.pick_best_screenshot()

                # If the new method failed, fall back to the old slow method.
                if not self.screenshot_path:
                    self.screenshot_path = self.download_screenshot()
            self.contacted_hosts = self.parse_contacted_hosts()
            self.dropped_files = self.parse_dropped_files()
            self.http_requests = self.parse_http_requests()
            self.dns_requests = self.parse_dns_requests()
            
            # Fix the HTTP requests. VxStream seems to like to say the HTTP request
            # was made using the IP address, but if there is a matching DNS request
            # for this IP, swap in the domain name instead.
            for http_request in self.http_requests:
                for dns_request in self.dns_requests:
                    if http_request.host == dns_request.answer:
                        http_request.host = dns_request.request
            
            self.process_tree = self.parse_process_tree()
            self.decoded_process_tree = self.decode_process_tree()
            self.process_tree_urls = self.parse_process_tree_urls()
            self.memory_urls = self.parse_memory_urls()
            self.mutexes = self.parse_mutexes()
            self.resolved_apis = self.parse_resolved_apis()
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
        return self.base_url + "/sample/" + str(self.sha256) + "?environmentId=" + str(self.sample_id)
    
    def pick_best_screenshot(self):
        potential_screenshots = [thing for thing in os.listdir(self.report_directory) if thing.startswith("screen_") and thing.endswith(".png")]
        if potential_screenshots:
            self.logger.debug("Picking the best screenshot using new method.")

            # Our VxStream VMs use the standard Windows background image, which
            # is quite large. In most cases, we want the medium filesize image.
            screenshots = {}
            for screenshot in potential_screenshots:
                path = os.path.join(self.report_directory, screenshot)
                size = int(os.path.getsize(path))
                screenshots[path] = size

            # Sort the screenshots by their size.
            screenshots = sorted(screenshots.items(), key=lambda x: x[1])

            # Find the middle index value.
            num_screenshots = len(screenshots)
            if num_screenshots % 2 == 0:
                best_screenshot_index = int(num_screenshots / 2)
            else:
                best_screenshot_index = int((num_screenshots / 2) - 0.5)

            # Grab the best screenshot.
            best_screenshot_path = screenshots[best_screenshot_index][0]

            # If we picked a best screenshot, return that as the path.
            if best_screenshot_path:
                # Rename the screenshot so it doesn't get overwritten on wiki pages
                # in the event one with the same name is uploaded to the page.
                new_name = "screen_" + self.md5 + ".png"
                new_path = os.path.join(os.path.dirname(best_screenshot_path), new_name)
                try:
                    os.rename(best_screenshot_path, new_path)
                    self.logger.debug("Picked best screenshot '{}' and moved it to '{}'".format(os.path.basename(best_screenshot_path), new_name))
                    return new_path
                except:
                    return None

    def download_screenshot(self):
        if self.screenshot_repository:
            screenshot_path = os.path.join(self.screenshot_repository, self.md5 + "_vxstream.png")

            if not os.path.exists(screenshot_path):
                url = self.parse_screenshot_url()

                if url:
                    try:
                        self.logger.debug("Downloading screenshot " + url)
                        request = requests.get(url, allow_redirects=True, verify=self.requests_verify)

                        if request.status_code == 200:
                            with open(screenshot_path, "wb") as url_file:
                                url_file.write(request.content)

                            return screenshot_path
                    except requests.exceptions.ConnectionError:
                        return None
            else:
                self.logger.debug("Screenshot already exists " + screenshot_path)
                return screenshot_path
        
        return None
    
    def parse_screenshot_url(self):
        self.logger.debug("Picking best screenshot")

        screenshot_files = self.parse(self.report, "analysis", "final", "imageprocessing", "image")
            
        # If the screenshot_files JSON is a dictionary, that means only
        # 1 screenshot was taken. In this case, we don't want the screenshot.
        if isinstance(screenshot_files, dict):
            return ""
            
        screenshot_url = ""
        if screenshot_files:
            if len(screenshot_files) > 1:
                # Create a list of each screenshot URL.
                screenshot_urls = []
                for screenshot in screenshot_files:
                    screenshot_urls.append(self.base_url + "/sample/" + self.sha256 + "%23" + str(self.sample_id) + "/screenshots/" + screenshot["file"])
            
                # Get the size of each screenshot. VxStream uses a large image for its
                # desktop background, so in most cases, the smallest size screenshot will
                # be the most interesting (for example a Word document with lots of white).
                try:
                    smallest_size = 9999999
                    for url in screenshot_urls:
                        try:
                            size = int(requests.head(url, verify=self.requests_verify).headers["content-length"])
                            if size < smallest_size:
                                smallest_size = size
                                screenshot_url = url
                        except KeyError:
                            pass
                except requests.exceptions.ConnectionError:
                    return ""
                        
        return screenshot_url
    
    def parse_http_requests(self):
        self.logger.debug("Parsing HTTP requests")

        http_requests = []
        http_requests_json = self.parse(self.report, "analysis", "runtime", "network", "httprequests", "request")

        if http_requests_json:
            if isinstance(http_requests_json, dict):
                http_requests_json = [http_requests_json]
                
            for request in http_requests_json:
                r = HttpRequest()
                
                try: r.host = request["host"]
                except KeyError: pass
                
                try: r.port = request["dest_port"]
                except KeyError: pass
                
                try: r.uri = request["request_url"]
                except KeyError: pass
                
                try: r.method = request["request_method"]
                except KeyError: pass
                
                try: r.user_agent = request["useragent"]
                except KeyError: pass
                
                # Only add the request if the host was successfully parsed.
                if r.host:
                    http_requests.append(r)
                    
        return http_requests
    
    def parse_dns_requests(self):
        self.logger.debug("Parsing DNS requests")

        dns_requests = []
        dns_requests_json = self.parse(self.report, "analysis", "runtime", "network", "domains", "domain")

        if dns_requests_json:
            if isinstance(dns_requests_json, dict):
                dns_requests_json = [dns_requests_json]
                
            if isinstance(dns_requests_json, str):
                dns_requests_json = [dns_requests_json]
                
            for request in dns_requests_json:
                r = DnsRequest()
                                
                try: r.request = request["db"]
                except KeyError: pass
                except TypeError: r.request = request
                
                try: r.answer = request["address"]
                except KeyError: pass
                except TypeError: pass
                
                # Only add the request if the host was successfully parsed.
                if r.request:
                    dns_requests.append(r)
                    
        return dns_requests

    def parse_dropped_files(self):
        self.logger.debug("Parsing dropped files")

        dropped_files = []
        dropped_files_json = self.parse(self.report, "analysis", "runtime", "dropped", "file")
                                                
        if dropped_files_json:
            if isinstance(dropped_files_json, dict):
                dropped_files_json = [dropped_files_json]

            for file in dropped_files_json:
                f = DroppedFile()
                
                try:
                    f.filename = file["filename"]
                    potential_path = os.path.join(self.report_directory, "dropped", f.filename)
                    if os.path.exists(potential_path):
                        f.os_path = potential_path
                except KeyError: pass

                try: f.path = file["vmpath"]
                except KeyError: pass
            
                try: f.size = file["filesize"]
                except KeyError: pass
            
                try: f.type = file["filetype"]
                except KeyError: pass
            
                try: f.md5 = file["md5"]
                except KeyError: pass
            
                try: f.sha1 = file["sha1"]
                except KeyError: pass
            
                try: f.sha256 = file["sha256"]
                except KeyError: pass
            
                try: f.sha512 = file["sha512"]
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
        contacted_hosts_json = self.parse(self.report, "analysis", "runtime", "network", "hosts", "host")
        
        if contacted_hosts_json:
            if isinstance(contacted_hosts_json, dict):
                contacted_hosts_json = [contacted_hosts_json]

            for host in contacted_hosts_json:
                h = ContactedHost()
                
                try: h.ipv4 = host["address"]
                except KeyError: pass
            
                try: h.port = host["port"]
                except KeyError: pass
            
                try: h.protocol = host["protocol"]
                except KeyError: pass
            
                try: h.location = host["country"] + " (ASN: " + str(host["asn"]) + " - " + host["as_owner"] + ")"
                except KeyError: pass

                # Associated domains are almost never good indicators. Very noisy.
                #try:
                #    associated_domains = host["associated_domains"]["domain"]
                #    if isinstance(associated_domains, dict):
                #        associated_domains = [associated_domains]
                #    
                #    for domain in associated_domains:
                #        h.add_associated_domain(domain["db"], domain["resolved"][:10])
                #except KeyError: pass
                #except TypeError: pass
                
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

        process_list = ProcessList()
        process_tree_json = self.parse(self.report, "analysis", "runtime", "targets", "target")
        
        if process_tree_json:
            if isinstance(process_tree_json, dict):
                process_tree_json = [process_tree_json]
                
            for process in process_tree_json:
                command = str(process["name"]) + " " + str(process["commandline"])
                pid = process["pid"]
                parent_pid = process["parentpid"]
                new_process = Process(command, pid, parent_pid)
                process_list.add_process(new_process)
                    
        return process_list

    def decode_process_tree(self):
        process_tree = str(self.parse_process_tree())
        decoded_process_tree = process_tree
        for chunk in process_tree.split():
            try:
                decoded_chunk = base64.b64decode(chunk).decode('utf-8')
                decoded_process_tree = decoded_process_tree.replace(chunk, decoded_chunk)
            except:
                pass

        if decoded_process_tree != process_tree:
            return decoded_process_tree
        else:
            return ''

    def parse_memory_urls(self):
        self.logger.debug("Parsing memory URLs")
        memory_urls = set()
        memory_urls_json = self.parse(self.report, "analysis", "hybridanalysis", "ipdomainstreams", "stream")
        
        if memory_urls_json:
            if isinstance(memory_urls_json, dict):
                memory_urls_json = [memory_urls_json]
                
            for url in memory_urls_json:
                if isinstance(url, str):
                    if RegexHelpers.is_url(url):
                        memory_urls.add(url)
                if isinstance(url, dict):
                    if "db" in url:
                        if RegexHelpers.is_url(url["db"]):
                            memory_urls.add(url["db"])

        return sorted(list(memory_urls))
    
    def parse_mutexes(self):
        self.logger.debug("Parsing mutexes")

        mutex_list = set()
        process_tree_json = self.parse(self.report, "analysis", "runtime", "targets", "target")
        
        if process_tree_json:
            if isinstance(process_tree_json, dict):
                process_tree_json = [process_tree_json]
                
            for process in process_tree_json:
                try:
                    mutexes = process["mutants"]["mutant"]
                
                    if isinstance(mutexes, dict):
                        mutexes = [mutexes]
                        
                    for mutex in mutexes:
                        mutex_list.add(mutex["db"])
                except TypeError:
                    pass
                except KeyError:
                    pass
                    
        return sorted(list(mutex_list))
    
    def parse_resolved_apis(self):
        self.logger.debug("Parsing resolved APIs")

        resolved_apis = set()
        hybrid_targets_json = self.parse(self.report, "analysis", "hybridanalysis", "targets", "target")
        
        if hybrid_targets_json:
            if isinstance(hybrid_targets_json, dict):
                hybrid_targets_json = [hybrid_targets_json]
                
            for target in hybrid_targets_json:
                try: streams = target["streams"]["stream"]
                except TypeError: streams = []
                
                if isinstance(streams, dict):
                    streams = [streams]
                    
                for stream in streams:
                    try:
                        api_calls = stream["header"]["apicalls"]["apicall"]
                    
                        if isinstance(api_calls, dict):
                            api_calls = [api_calls]
                        
                        for api_call in api_calls:
                            resolved_apis.add(api_call["symbol"]["db"])
                    except KeyError:
                        pass
                    except TypeError:
                        pass
                        
        return sorted(list(resolved_apis))
    
    def parse_strings_urls(self):
        self.logger.debug("Looking for URLs in strings")
        return RegexHelpers.find_urls(self.parse_strings())
    
    def parse_strings(self):
        self.logger.debug("Parsing strings")
        strings_json = self.parse(self.report, "analysis", "final", "strings", "string")
        strings_list = []
        
        if strings_json:
            if isinstance(strings_json, dict):
                strings_json = [strings_json]
                
            for string in strings_json:
                try: strings_list.append(string["db"])
                except KeyError: pass
            
        return "\n".join(strings_list)
