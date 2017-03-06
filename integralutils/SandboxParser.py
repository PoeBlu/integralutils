import os
import sys
import requests

from integralutils import Indicator
from integralutils import JsonConfigParser as jcp
from integralutils import RegexHelpers

class SandboxParser():
    def __init__(self, sandbox_name, json_path, config_path=None, requests_verify=True, check_whitelist=True):
        # This can be set to a path to a custom CA cert as well.
        self.requests_verify = requests_verify
        
        # If we weren't given a config path, assume we want to load
        # the one shipped with integralutils.
        if not config_path:
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "etc", "sandbox_json_config.ini")
        
        self.json_path = json_path
        self.json_parser = jcp.JsonConfigParser(config_path, self.json_path)
        self.json_parser.parse_section(sandbox_name)
        
        # A place to store any indicators from the parsed report.
        self.iocs = []

        self.sandbox_host = self.json_parser.get_value("sandbox_host")
        self.sandbox_directory = os.path.dirname(self.json_path)
        self.sandbox_name = self.json_parser.get_value("sandbox_name")
        self.sandbox_display_name = self.json_parser.get_value("sandbox_display_name")
        self.sandbox_sample_id = self.json_parser.get_value("sandbox_sample_id")
        self.sandbox_vm_name = self.json_parser.get_value("sandbox_vm_name")
        self.md5 = self.json_parser.get_value("md5")
        self.sha1 = self.json_parser.get_value("sha1")
        self.sha256 = self.json_parser.get_value("sha256")
        self.sha512 = self.json_parser.get_value("sha512")
        self.ssdeep = self.json_parser.get_value("ssdeep")
        
        # Per our JsonConfigParser config settings, there could be multiple filename entries.
        # If that is the case, let's just take the first value that isn't a hash (VxStream).
        filenames = self.json_parser.get_value("filename")
        if filenames and isinstance(filenames, list):
            for filename in filenames:
                if not RegexHelpers.is_sha256(filename):
                    self.filename = filename
        elif isinstance(filenames, str):
            self.filename = filenames
        else:
            self.filename = "Unknown"
            
        # The rest of the JSON values need to be standardized since they aren't
        # simply normal strings. We'll dynamically call the correct function
        # based on the sandbox name we were given. To do this, we first need to
        # get a list of every key name in the config file, regardless of its section.
        config_keys = set()
        for section in self.json_parser._config.sections():
            for key in self.json_parser._config[section].keys():
                config_keys.add(key)

        # Now we have a list of all of the key names that our SandboxParser should contain.
        # This is a list of each unique key from each sandbox section in the config file.
        # We can loop over this list and check whether or not we need to dynamically call
        # a function in order to standardize the values.
        for key in config_keys:
            # If we didn't already set this key earlier...
            if not hasattr(self, key):
                func_name = self.sandbox_name + "_" + key
                # If we've defined a function for this key, call it.
                if hasattr(self, func_name):
                    func = getattr(self, func_name)
                    setattr(self, key, func())
                # Otherwise, just set the key to an empty list.
                else:
                    setattr(self, key, [])
                    
        # Make an Indicator for the sample's MD5 hash.
        if hasattr(self, "md5"):
            if RegexHelpers.is_md5(self.md5):
                try:
                    ind = Indicator.Indicator(self.md5, "Hash - MD5")
                    ind.add_tags("sandboxed_sample")
                    self.iocs.append(ind)
                except ValueError:
                    pass
        
        # Make an Indicator for the sample's SHA1 hash.
        if hasattr(self, "sha1"):
             if RegexHelpers.is_sha1(self.sha1):
                try:
                    ind = Indicator.Indicator(self.sha1, "Hash - SHA1")
                    ind.add_tags("sandboxed_sample")
                    self.iocs.append(ind)
                except ValueError:
                    pass
            
        # Make an Indicator for the sample's SHA256 hash.
        if hasattr(self, "sha256"):
            if RegexHelpers.is_sha256(self.sha256):
                try:
                    ind = Indicator.Indicator(self.sha256, "Hash - SHA256")
                    ind.add_tags("sandboxed_sample")
                    self.iocs.append(ind)
                except ValueError:
                    pass
            
        # Make Indicators for any contacted hosts.
        if hasattr(self, "contacted_hosts"):
            for host in self.contacted_hosts:
                # Make an Indicator for the IP itself.
                if RegexHelpers.is_ip(host.ipv4):
                    try:
                        ind = Indicator.Indicator(host.ipv4, "Address - ipv4-addr")
                        ind.add_tags("contacted_host")
                        if host.protocol and host.port:
                            ind.add_tags(host.protocol + " " + host.port)
                        elif host.protocol and not host.port:
                            indicator.add_tag(host.protocol)
                        self.iocs.append(ind)
                    except ValueError:
                        pass
                
                    # Make Indicators for any associated domains.
                    for domain in host.associated_domains:
                        if RegexHelpers.is_domain(domain["domain"]):
                            try:
                                ind = Indicator.Indicator(domain["domain"], "URI - Domain Name")
                                ind.add_tags("associated_to_" + host.ipv4)
                                ind.add_relationships(host.ipv4)
                                self.iocs.append(ind)
                            except ValueError:
                                pass

        # Make Indicators for any DNS requests.
        if hasattr(self, "dns_requests"):
            for request in self.dns_requests:
                # Make an Indicator for the requested domain.
                if RegexHelpers.is_domain(request.request):
                    try:
                        ind = Indicator.Indicator(request.request, "URI - Domain Name")
                        ind.add_tags("dns_request")
                        # If the DNS answer is an IP, add a tag for it and
                        # also create an Indicator for it.
                        if RegexHelpers.is_ip(request.answer):
                            ind.add_tags(request.answer)
                            
                            try:
                                ip_ind = Indicator.Indicator(request.answer, "Address - ipv4-addr")
                                ip_ind.add_tags(["dns_response", request.request])
                                self.iocs.append(ip_ind)
                            except ValueError:
                                pass
                        
                        self.iocs.append(ind)
                    except ValueError:
                        pass
                
        # Make Indicators for any dropped files.
        # TODO: Add back in the ability to only make Indicators for "interesting"
        # dropped files, based on file type or file extension.
        if hasattr(self, "dropped_files"):
            for file in self.dropped_files:
                # Make an Indicator for the filename.
                try:
                    ind = Indicator.Indicator(file.filename, "Windows - FileName")
                    ind.add_tags("dropped_file")
                    self.iocs.append(ind)
                except ValueError:
                    pass
                
                # Make an Indicator for the MD5 hash.
                if RegexHelpers.is_md5(file.md5):
                    try:
                        ind = Indicator.Indicator(file.md5, "Hash - MD5")
                        ind.add_tags([file.filename, "dropped_file"])
                        ind.add_relationships(file.filename)
                        self.iocs.append(ind)
                    except ValueError:
                        pass
                    
                # Make an Indicator for the SHA1 hash.
                if RegexHelpers.is_sha1(file.sha1):
                    try:
                        ind = Indicator.Indicator(file.sha1, "Hash - SHA1")
                        ind.add_tags([file.filename, "dropped_file"])
                        ind.add_relationships(file.filename)
                        self.iocs.append(ind)
                    except ValueError:
                        pass
                    
                # Make an Indicator for the SHA256 hash.
                if RegexHelpers.is_sha256(file.sha256):
                    try:
                        ind = Indicator.Indicator(file.sha256, "Hash - SHA256")
                        ind.add_tags([file.filename, "dropped_file"])
                        ind.add_relationships(file.filename)
                        self.iocs.append(ind)
                    except ValueError:
                        pass
                    
        # Make Indicators for any HTTP requests.
        if hasattr(self, "http_requests"):
            for request in self.http_requests:
                # Check if the host is a domain or IP.
                if RegexHelpers.is_ip(request.host):
                    indicator_type = "Address - ipv4-addr"
                # Otherwise it must be a domain.
                else:
                    indicator_type = "URI - Domain Name"
                    
                # Make an Indicator for the host.
                try:
                    ind = Indicator.Indicator(request.host, indicator_type)
                    ind.add_tags(["http_request", request.method])
                    if request.method == "POST":
                        ind.add_tags("c2")
                    self.iocs.append(ind)
                except ValueError:
                    pass

                # Make an Indicator for the URI path.
                if request.uri != "/":
                    try:
                        ind = Indicator.Indicator(request.uri, "URI - Path")
                        ind.add_tags(["http_request", request.method, request.host])
                        if request.method == "POST":
                            ind.add_tags("c2")
                        ind.add_relationships(request.host)
                        self.iocs.append(ind)
                    except ValueError:
                        pass

                # Make an Indicator for the full URL.
                try:
                    url = "http://" + request.host + request.uri
                    ind = Indicator.Indicator(url, "URI - URL")
                    ind.add_tags(["http_request", request.method])
                    if request.method == "POST":
                        ind.add_tags("c2")
                    ind.add_relationships([request.host, request.uri])
                    self.iocs.append(ind)
                except ValueError:
                    pass
                
                # Make an Indicator for the User-Agent.
                try:
                    ind = Indicator.Indicator(request.user_agent, "URI - HTTP - UserAgent")
                    ind.add_tags(["http_request", request.method, request.host])
                    if request.method == "POST":
                        ind.add_tags("c2")
                    ind.add_relationships([request.host, request.uri])
                    self.iocs.append(ind)
                except ValueError:
                    pass
                
        # Make Indicators for any memory URLs. Currently, only VxStream
        # has this memory URL feature.
        if hasattr(self, "memory_urls"):
            indicator_list = Indicator.generate_url_indicators(self.memory_urls)
            
            # Add some extra tags to the generated indicators and
            # then add them to our main IOC list.
            for ind in indicator_list:
                ind.add_tags("url_in_memory")
                self.iocs.append(ind)
                
        # Make Indicators for any URLs found in the sample's strings.
        if hasattr(self, "strings_urls"):
            indicator_list = Indicator.generate_url_indicators(self.strings_urls)
            
            # Add some extra tags to the generated indicators and
            # then add them to our main IOC list.
            for ind in indicator_list:
                ind.add_tags("url_in_strings")
                self.iocs.append(ind)

        # Make Indicators for any URLs found in the sample's process tree.
        if hasattr(self, "process_tree_urls"):
            indicator_list = Indicator.generate_url_indicators(self.process_tree_urls)
            
            # Add some extra tags to the generated indicators and
            # then add them to our main IOC list.
            for ind in indicator_list:
                ind.add_tags("url_in_process_tree")
                self.iocs.append(ind)

        # Make Indicators for any mutexes.
        if hasattr(self, "mutexes"):
            for mutex in self.mutexes:
                try:
                    ind = Indicator.Indicator(mutex, "Windows - Mutex")
                    ind.add_tags("mutex_created")
                    self.iocs.append(ind)
                except ValueError:
                    pass
                
        # Run the IOCs through the whitelists if requested.
        if check_whitelist:
            self.iocs = Indicator.run_whitelist(self.iocs)
            
        # Finally merge the IOCs so we don't have any duplicates.
        self.iocs = Indicator.merge_duplicate_indicators(self.iocs)

    # The following functions correspond to the sections and keys defined in
    # your config file. The format is: <section>_<key>
    #
    # So in the case of VxStream, we have a "vxstream" section in the config
    # file. Under the vxstream section, we have a key called "sandbox_url".
    # Thus, we need to create a function here called "vxstream_sandbox_url"
    # and have it parse or return the data however we need it.
    
    ####################
    ##                ##
    ##    VXSTREAM    ##
    ##                ##
    ####################
    def vxstream_sandbox_url(self):
        return self.sandbox_host + "/sample/" + str(self.sha256) + "?environmentId=" + str(self.sandbox_sample_id)

    def vxstream_screenshot_url(self):
        screenshot_files = self.json_parser.get_value("screenshot_url")
            
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
                    screenshot_urls.append(self.sandbox_host + "/sample/" + self.sha256 + "%23" + str(self.sandbox_sample_id) + "/screenshots/" + screenshot["file"])
            
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

    def vxstream_malware_family(self):
        dropped_files = self.json_parser.get_value("dropped_files")
        
        for file in dropped_files:
            yarahits = self.json_parser._safe_parse(file, "static,yarahits", error=[])
            
            if isinstance(yarahits, dict):
                yarahits = [yarahits]
                
            for hit in yarahits:
                rule_name = hit["rule"]["name"].title()
                if rule_name:
                    return rule_name
                
    def vxstream_http_requests(self):
        http_requests = []
        http_requests_json = self.json_parser.get_value("http_requests")

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

    def vxstream_dns_requests(self):
        dns_requests = []
        dns_requests_json = self.json_parser.get_value("dns_requests")

        if dns_requests_json:
            if isinstance(dns_requests_json, dict):
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
                
    def vxstream_dropped_files(self):
        dropped_files = []
        dropped_files_json = self.json_parser.get_value("dropped_files")
                                                
        if dropped_files_json:
            if isinstance(dropped_files_json, dict):
                dropped_files_json = [dropped_files_json]

            for file in dropped_files_json:
                f = DroppedFile()
                
                try:
                    f.filename = file["filename"]
                    potential_path = os.path.join(self.sandbox_directory, "dropped", f.filename)
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
                    dropped_files.append(f)

        return dropped_files

    def vxstream_contacted_hosts(self):
        contacted_hosts = []
        contacted_hosts_json = self.json_parser.get_value("contacted_hosts")
        
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

                try:
                    associated_domains = host["associated_domains"]["domain"]
                    if isinstance(associated_domains, dict):
                        associated_domains = [associated_domains]
                    
                    for domain in associated_domains:
                        h.add_associated_domain(domain["db"], domain["resolved"][:10])
                except KeyError: pass
                except TypeError: pass
                
                # Only add the host if its IP was succesfully parsed.
                if h.ipv4:
                    contacted_hosts.append(h)
                
        return contacted_hosts
    
    def vxstream_process_tree_urls(self):
        return RegexHelpers.find_urls(str(self.vxstream_process_tree()))

    def vxstream_process_tree(self):
        process_list = ProcessList()
        process_tree_json = self.json_parser.get_value("process_tree")
        
        if process_tree_json:
            if isinstance(process_tree_json, dict):
                process_tree_json = [process_tree_json]
                
            for process in process_tree_json:
                command = process["name"] + " " + process["commandline"]
                pid = process["pid"]
                parent_pid = process["parentpid"]
                new_process = Process(command, pid, parent_pid)
                process_list.add_process(new_process)
                    
        return process_list

    def vxstream_memory_urls(self):
        memory_urls = set()
        memory_urls_json = self.json_parser.get_value("memory_urls")
        
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

    def vxstream_mutexes(self):
        mutex_list = set()
        process_tree_json = self.json_parser.get_value("process_tree")
        
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
                    
        return sorted(list(mutex_list))

    def vxstream_resolved_apis(self):
        resolved_apis = set()
        hybrid_targets_json = self.json_parser.get_value("resolved_apis")
        
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
    
    def vxstream_strings_urls(self):
        return RegexHelpers.find_urls(self.vxstream_strings())

    def vxstream_strings(self):
        strings_json = self.json_parser.get_value("strings")
        strings_list = []
        
        if strings_json:
            if isinstance(strings_json, dict):
                strings_json = [strings_json]
                
            for string in strings_json:
                try: strings_list.append(string["db"])
                except KeyError: pass
            
        return "\n".join(strings_list)
            
    
    ##################
    ##              ##
    ##    CUCKOO    ##
    ##              ##
    ##################
    def cuckoo_sandbox_url(self):
        return self.sandbox_host + "/analysis/" + str(self.sandbox_sample_id) + "/"
    
    def cuckoo_screenshot_url(self):
        # The Cuckoo JSON does not tell us how many screenshots are available,
        # so we must perform a HTTP HEAD request loop until we no longer receive
        # an image. After the loop is finished, we want to get the URL of the
        # largest image. Cuckoo uses a plain black background for the sandbox VM,
        # so the largest image should in theory have something interesting in it.
    
        # Start the HTTP HEAD loop with 0001
        image_int = 1
        image_number = str(image_int).zfill(4)
        url = self.sandbox_host + "/file/screenshot/" + str(self.sandbox_sample_id) + "/" + image_number + "/"

        # Keep a dictionary to store the image URLs and their size.
        screenshot_dict = {}
    
        try:
            # Perform the first HTTP HEAD request.
            req = requests.head(url, allow_redirects=True, verify=self.requests_verify)

            # Loop until we no longer receive an image.
            while req.headers["content-type"] == "image/jpeg":
                screenshot_dict[url] = int(req.headers["content-length"])
                image_int += 1
                image_number = str(image_int).zfill(4)
                url = self.sandbox_host + "/file/screenshot/" + str(self.sandbox_sample_id) + "/" + image_number + "/"
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
    
    def cuckoo_malware_family(self):
        return self.json_parser.get_value("malware_family")
    
    def cuckoo_http_requests(self):
        http_requests = []
        http_requests_json = self.json_parser.get_value("http_requests")
        
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
    
    def cuckoo_dns_requests(self):
        dns_requests = []
        dns_requests_json = self.json_parser.get_value("dns_requests")
        
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
        
    def cuckoo_dropped_files(self):
        dropped_files = []
        dropped_files_json = self.json_parser.get_value("dropped_files")
                                                
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
                    potential_path = os.path.join(self.sandbox_directory, "dropped", f.sha256)
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
    
    def cuckoo_contacted_hosts(self):
        contacted_hosts = []
        contacted_hosts_json = self.json_parser.get_value("contacted_hosts")
        
        if contacted_hosts_json:
            for host in contacted_hosts_json:
                h = ContactedHost()
                
                try: h.ipv4 = host["ip"]
                except KeyError: pass
            
                try: h.location = host["country_name"]
                except KeyError: pass

                try:
                    if host["hostname"]:
                        h.add_associated_domain(host["hostname"])
                except KeyError: pass
                
                # Only add the host if its IP was succesfully parsed.
                if h.ipv4:
                    contacted_hosts.append(h)
                
        return contacted_hosts
    
    def cuckoo_process_tree_urls(self):
        return RegexHelpers.find_urls(str(self.cuckoo_process_tree()))
    
    def cuckoo_process_tree(self):
        def walk_tree(process_json=None, process_list=None):
            if not process_list:
                process_list = ProcessList()
            
            for process in process_json:
                command = process["environ"]["CommandLine"]
                pid = process["pid"]
                parent_pid = process["parent_id"]
                new_process = Process(command, pid, parent_pid)
                process_list.add_process(new_process)
                process_list = walk_tree(process["children"], process_list)
                
            return process_list
                
        return walk_tree(process_json=self.json_parser.get_value("process_tree")) 
        
    def cuckoo_mutexes(self):
        mutexes = set()
        mutexes_json = self.json_parser.get_value("mutexes")
        
        if mutexes_json:
            for mutex in mutexes_json:
                mutexes.add(mutex)
                
        return sorted(list(mutexes))
    
    def cuckoo_resolved_apis(self):
        resolved_apis = set()
        resolved_apis_json = self.json_parser.get_value("resolved_apis")
        
        if resolved_apis_json:
            for api_call in resolved_apis_json:
                resolved_apis.add(api_call)
                
        return sorted(list(resolved_apis))
    
    def cuckoo_created_services(self):
        created_services = set()
        created_services_json = self.json_parser.get_value("created_services")
        
        if created_services_json:
            for service in created_services_json:
                created_services.add(service)
                
        return sorted(list(created_services))
    
    def cuckoo_started_services(self):
        started_services = set()
        started_services_json = self.json_parser.get_value("started_services")
        
        if started_services_json:
            for service in started_services_json:
                started_services.add(service)
                
        return sorted(list(started_services))
    
    def cuckoo_strings_urls(self):
        print("RUNNING CUCKOO_STRINGS_URLS!")
        return RegexHelpers.find_urls(self.cuckoo_strings())
    
    def cuckoo_strings(self):
        strings_json = self.json_parser.get_value("strings")
        return "\n".join(strings_json)
        
    ####################
    ##                ##
    ##    WILDFIRE    ##
    ##                ##
    ####################
    def wildfire_sandbox_url(self):
        if self.sha256:
            return "https://wildfire.paloaltonetworks.com/wildfire/reportlist?search=" + self.sha256
        else:
            return ""
        
    def wildfire_http_requests(self):
        reports_json = self.json_parser.get_value("reports")
        
        # In case there was only a single report, make it a list anyway.
        if isinstance(reports_json, dict):
            reports_json = [reports_json]
            
        # We use a set instead of a list since there are multiple Wildfire reports.
        # This prevents any duplicate requests being returned.
        http_requests = set()
        
        # Loop over each Wildfire report (usually should be 2).
        for report in reports_json:
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
        
        return list(http_requests)
    
    def wildfire_dns_requests(self):
        reports_json = self.json_parser.get_value("reports")
        
        # In case there was only a single report, make it a list anyway.
        if isinstance(reports_json, dict):
            reports_json = [reports_json]
            
        # We use a set instead of a list since there are multiple Wildfire reports.
        # This prevents any duplicate requests being returned.
        dns_requests = set()
        
        # Loop over each Wildfire report (usually should be 2).
        for report in reports_json:
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
        
        return list(dns_requests)
    
    def wildfire_dropped_files(self):
        reports_json = self.json_parser.get_value("reports")
        
        # In case there was only a single report, make it a list anyway.
        if isinstance(reports_json, dict):
            reports_json = [reports_json]
            
        # We use a set instead of a list since there are multiple Wildfire reports.
        # This prevents any duplicate requests being returned.
        dropped_files = set()
        
        # Loop over each Wildfire report (usually should be 2).
        for report in reports_json:
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
        
        return list(dropped_files)
    
    def wildfire_contacted_hosts(self):
        reports_json = self.json_parser.get_value("reports")
        
        # In case there was only a single report, make it a list anyway.
        if isinstance(reports_json, dict):
            reports_json = [reports_json]
            
        # We use a set instead of a list since there are multiple Wildfire reports.
        # This prevents any duplicate hosts being returned.
        contacted_hosts = set()
        
        # Loop over each Wildfire report (usually should be 2).
        for report in reports_json:
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
        
        return list(contacted_hosts)
    
    def wildfire_process_tree_urls(self):
        return RegexHelpers.find_urls(str(self.wildfire_process_tree()))
    
    def wildfire_process_tree(self):
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
                
            return process_list
                
        reports_json = self.json_parser.get_value("reports")
        
        # In case there was only a single report, make it a list anyway.
        if isinstance(reports_json, dict):
            reports_json = [reports_json]
            
        process_tree_to_use = None
        process_tree_to_use_size = 0
        for report in reports_json:
            try:
                process_tree = report["process_tree"]["process"]
                process_tree_size = sys.getsizeof(process_tree)
                if process_tree_size > process_tree_to_use_size:
                    process_tree_to_use = process_tree
                    process_tree_to_use_size = process_tree_size
            except KeyError:
                pass

        return walk_tree(process_json=process_tree_to_use) 
    
    def wildfire_memory_urls(self):
        memory_urls = set()
        
        process_tree = str(self.wildfire_process_tree)
        process_tree_urls = RegexHelpers.find_urls(process_tree)
        for url in process_tree_urls:
            memory_urls.add(url[0])
                
        return sorted(list(memory_urls))
    
    def wildfire_mutexes(self):
        reports_json = self.json_parser.get_value("reports")
        
        # In case there was only a single report, make it a list anyway.
        if isinstance(reports_json, dict):
            reports_json = [reports_json]
            
        # We use a set instead of a list since there are multiple Wildfire reports.
        # This prevents any duplicate mutexes being returned.
        mutexes = set()
        
        # Loop over each Wildfire report (usually should be 2).
        for report in reports_json:
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
        
        return list(mutexes)


class Process():
    def __init__(self, command, pid, parent_pid):
        self.command = command
        self.pid = pid
        self.parent_pid = parent_pid
        
    @property
    def command(self):
        return self.__command
    
    @command.setter
    def command(self, command):
        if isinstance(command, str):
            self.__command = command
        else:
            self.__command = ""
            
    @property
    def pid(self):
        return self.__pid
    
    @pid.setter
    def pid(self, pid):
        self.__pid = str(pid)
        
    @property
    def parent_pid(self):
        return self.__parent_pid
    
    @parent_pid.setter
    def parent_pid(self, parent_pid):
        self.__parent_pid = str(parent_pid)
        
class ProcessList():
    def __init__(self):
        self._list = []
    
    def add_process(self, new_process):
        if isinstance(new_process, Process):
            self._list.append(new_process)
            
    def structure(self):
        # Operate on a copy of the list.
        tree = self._list[:]
        
        # Get a list of process ID's.
        pid_list = [proc.pid for proc in tree]
    
        # Get a list of the "root" process ID's.
        root_pids = [proc.pid for proc in tree if proc.parent_pid not in pid_list]
        
        # Loop over the process list.
        for process in tree:
            # Set the "children" equal to a list of its child PIDs.
            process.children = [proc for proc in tree if proc.parent_pid == process.pid]
            
        # At this point we have some duplicate elements in self._list that
        # appear at the root process level that need to be removed.
        return [proc for proc in tree if proc.pid in root_pids]
    
    def __str__(self, process_tree=None, text="", depth=0):
        if not process_tree:
            process_tree = self.structure()
            
        for process in process_tree:
            text += "  " * depth + " " + process.command + "\n"

            if process.children:
                text = self.__str__(process.children, text, depth+1)

        return text
    
class DnsRequest():
    def __init__(self):
        self.request = ""
        self.type = ""
        self.answer = ""
        self.answer_type = ""
        
    def __hash__(self):
        return hash(self.request+self.type+self.answer+self.answer_type)
    
    def __eq__(self, other):
        if isinstance(other, DnsRequest):
            return self.request == other.request and self.type == other.type and self.answer == other.answer and self.answer_type == other.answer_type
        else:
            return False
        
    @property
    def request(self):
        return self.__request
    
    @request.setter
    def request(self, request):
        if isinstance(request, str):
            self.__request = request
        else:
            self.__request = ""
            
    @property
    def type(self):
        return self.__type
    
    @type.setter
    def type(self, type):
        if isinstance(type, str):
            self.__type = type
        else:
            self.__type = ""
            
    @property
    def answer(self):
        return self.__answer
    
    @answer.setter
    def answer(self, answer):
        if isinstance(answer, str):
            self.__answer = answer
        else:
            self.__answer = ""
            
    @property
    def answer_type(self):
        return self.__answer_type
    
    @answer_type.setter
    def answer_type(self, answer_type):
        if isinstance(answer_type, str):
            self.__answer_type = answer_type
        else:
            self.__answer_type = ""
    
class HttpRequest():
    def __init__(self):
        self.host = ""
        self.port = ""
        self.uri = ""
        self.method = ""
        self.user_agent = ""
    
    def __hash__(self):
        return hash(self.host+self.port+self.uri+self.method+self.user_agent)
    
    def __eq__(self, other):
        if isinstance(other, HttpRequest):
            return self.host == other.host and self.port == other.port and self.uri == other.uri and self.method == other.method and self.user_agent == other.user_agent
        else:
            return False
        
    @property
    def host(self):
        return self.__host
    
    @host.setter
    def host(self, host):
        if isinstance(host, str):
            self.__host = host
        else:
            self.__host = ""
            
    @property
    def port(self):
        return self.__port
    
    @port.setter
    def port(self, port):
        self.__port = str(port)
        
    @property
    def uri(self):
        return self.__uri
    
    @uri.setter
    def uri(self, uri):
        if isinstance(uri, str):
            self.__uri = uri
        else:
            self.__uri = ""
            
    @property
    def method(self):
        return self.__method
    
    @method.setter
    def method(self, method):
        if isinstance(method, str):
            self.__method = method
        else:
            self.__method = ""
            
    @property
    def user_agent(self):
        return self.__user_agent
    
    @user_agent.setter
    def user_agent(self, user_agent):
        if isinstance(user_agent, str):
            self.__user_agent = user_agent
        else:
            self.__user_agent = ""

class DroppedFile():
    def __init__(self):
        self.filename = ""
        self.path = ""
        self.os_path = ""
        self.size = ""
        self.type = ""
        self.md5 = ""
        self.sha1 = ""
        self.sha256 = ""
        self.sha512 = ""
        self.ssdeep = ""
        
    def __hash__(self):
        return hash(self.filename+self.path+self.size+self.type+self.md5+self.sha1+self.sha256+self.sha512+self.ssdeep)
    
    def __eq__(self, other):
        if isinstance(other, DroppedFile):
            return self.filename == other.filename and self.path == other.path and self.size == other.size and self.type == other.type and self.md5 == other.md5 and self.sha1 == other.sha1 and self.sha256 == other.sha256 and self.sha512 == other.sha512 and self.ssdeep == other.ssdeep
        else:
            return False
        
    @property
    def filename(self):
        return self.__filename
    
    @filename.setter
    def filename(self, filename):
        if isinstance(filename, str):
            self.__filename = filename
        else:
            self.__filename = ""
            
    @property
    def path(self):
        return self.__path
    
    @path.setter
    def path(self, path):
        if isinstance(path, str):
            self.__path = path
        else:
            self.__path = ""
            
    @property
    def os_path(self):
        return self.__os_path
    
    @os_path.setter
    def os_path(self, path):
        if isinstance(path, str):
            self.__os_path = path
        else:
            self.__os_path = ""
            
    @property
    def size(self):
        return self.__size
    
    @size.setter
    def size(self, size):
        try:
            size = int(size)
            if size < 0:
                size = 0
            self.__size = str(size)
        except ValueError:
            self.__size = ""
        
    @property
    def md5(self):
        return self.__md5
    
    @md5.setter
    def md5(self, hash):
        if RegexHelpers.is_md5(hash):
            self.__md5 = hash
        else:
            self.__md5 = ""
            
    @property
    def sha1(self):
        return self.__sha1
    
    @sha1.setter
    def sha1(self, hash):
        if RegexHelpers.is_sha1(hash):
            self.__sha1 = hash
        else:
            self.__sha1 = ""
            
    @property
    def sha256(self):
        return self.__sha256
    
    @sha256.setter
    def sha256(self, hash):
        if RegexHelpers.is_sha256(hash):
            self.__sha256 = hash
        else:
            self.__sha256 = ""
            
    @property
    def sha512(self):
        return self.__sha512
    
    @sha512.setter
    def sha512(self, hash):
        if RegexHelpers.is_sha512(hash):
            self.__sha512 = hash
        else:
            self.__sha512 = ""
            
    @property
    def ssdeep(self):
        return self.__ssdeep
    
    @ssdeep.setter
    def ssdeep(self, hash):
        if isinstance(hash, str):
            self.__ssdeep = hash
        else:
            self.__ssdeep = ""

class ContactedHost():
    def __init__(self):
        self.ipv4 = ""
        self.port = ""
        self.protocol = ""
        self.location = ""
        self.associated_domains = []
        
    @property
    def ipv4(self):
        return self.__ipv4
    
    @ipv4.setter
    def ipv4(self, ip):
        if RegexHelpers.is_ip(ip):
            self.__ipv4 = ip
        else:
            self.__ipv4 = ""
            
    @property
    def port(self):
        return self.__port
    
    @port.setter
    def port(self, port):
        if port:
            port = int(port)
            if port < 1:
                self.__port = ""
            elif port > 65535:
                self.__port = ""
            else:
                self.__port = str(port)
        else:
            self.__port = ""
            
    @property
    def protocol(self):
        return self.__protocol
    
    @protocol.setter
    def protocol(self, protocol):
        if isinstance(protocol, str):
            self.__protocol = protocol
        else:
            self.__protocol = ""
            
    @property
    def location(self):
        return self.__location
    
    @location.setter
    def location(self, location):
        if isinstance(location, str):
            self.__location = location
        else:
            self.__location = ""
            
    @property
    def associated_domains(self):
        return self.__associated_domains
    
    @associated_domains.setter
    def associated_domains(self, assoc_list):
        if isinstance(assoc_list, list):
            self.__associated_domains = assoc_list
        else:
            self.__associated_domains = []
    
    def add_associated_domain(self, domain, date="00/00/0000"):
        associated = {"domain": domain, "date": date}
        self.associated_domains.append(associated)
