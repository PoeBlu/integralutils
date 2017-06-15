import hashlib
import json
import logging
import os
import pickle
import re
import sys

# Make sure the current directory is in the
# path so that we can run this from anywhere.
this_dir = os.path.dirname(__file__)
if this_dir not in sys.path:
    sys.path.insert(0, this_dir)

import RegexHelpers
import Indicator
import Whitelist

def detect_sandbox(json_path):
    logger = logging.getLogger()

    # Load the sandbox JSON.
    logger.debug("Detecting sandbox report JSON: " + json_path)
    with open(json_path) as json_data:
        report = json.load(json_data)

    # Check for mainline Cuckoo.
    try:
        id_key = report["target"]["file"]["md5"]
        if id_key and "malfamily" not in report:
            logger.debug("Detected Cuckoo.")
            return "cuckoo"
    except Exception:
        pass

    # Check for Spender Cuckoo.
    try:
        id_key = report["target"]["file"]["md5"]
        if id_key and "malfamily" in report:
            logger.debug("Detected Spender Cuckoo.")
            return "spendercuckoo"
    except Exception:
        pass

    # Check for VxStream.
    try:
        id_key = report["analysis"]["general"]["digests"]["md5"]
        if id_key:
            logger.debug("Detected VxStream.")
            return "vxstream"
    except Exception:
        pass

    # Check for Wildfire.
    try:
        id_key = report["wildfire"]["file_info"]["md5"]
        if id_key:
            logger.debug("Detected Wildfire.")
            return "wildfire"
    except Exception:
        pass

    logger.error("Unable to detect sandbox.")
    return ""

class BaseSandboxParser():
    def __init__(self, config, json_path=None, whitelister=None):
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

        self.iocs                 = []
        self.sandbox_name         = ""
        self.sandbox_display_name = ""
        self.sandbox_vm_name      = ""
        self.sandbox_url          = ""
        self.screenshot_path      = ""
        self.filename             = ""
        self.md5                  = ""
        self.sha1                 = ""
        self.sha256               = ""
        self.sha512               = ""
        self.ssdeep               = ""
        self.malware_family       = ""
        self.contacted_hosts      = []
        self.dropped_files        = []
        self.http_requests        = []
        self.dns_requests         = []
        self.process_tree         = []
        self.process_tree_urls    = []
        self.memory_urls          = []
        self.strings              = []
        self.strings_urls         = []
        self.mutexes              = []
        self.resolved_apis        = []
        self.created_services     = []
        self.started_services     = []
        
        # Figure out where we want to save the screenshots.
        repo_path = ""
        if "screenshot_repository" in self.config["BaseSandboxParser"]:
            this_dir = os.path.dirname(__file__)
            repo_path = os.path.realpath(os.path.join(this_dir, self.config["BaseSandboxParser"]["screenshot_repository"]))
            self.logger.debug("Saving screenshots to cache: " + repo_path)

        if os.path.exists(repo_path):
            self.screenshot_repository = repo_path
        else:
            self.screenshot_repository = ""

        # Figure out where we want to save the sandbox cache.
        cache_path = ""
        if "sandbox_cache" in self.config["BaseSandboxParser"]:
            this_dir = os.path.dirname(__file__)
            cache_path = os.path.realpath(os.path.join(this_dir, self.config["BaseSandboxParser"]["sandbox_cache"]))
            self.logger.debug("Saving sandbox cache to: " + cache_path)

        if os.path.exists(cache_path):
            self.cache_path = cache_path
        else:
            self.cache_path = ""
        
        # Load the report's JSON.
        if json_path:
            self.logger.debug("Loading sandbox JSON: " + json_path)
            self.json_path = json_path
            self.report = self.load_json(json_path)

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

    def __eq__(self, other):
        if isinstance(other, BaseSandboxParser):
            return (self.md5 == other.md5) and (self.sandbox_url == other.sandbox_url)
        else:
            return False
            
    def __hash__(self):
        return hash((self.md5, self.sandbox_url))

    # Function to load this report from the sandbox cache.
    def load_from_cache(self):
        if self.cache_path:
            report_md5 = self.md5_file_path(self.json_path)
            saved_report_path = os.path.join(self.cache_path, report_md5)

            if os.path.exists(saved_report_path):
                self.logger.info("Loading sandbox report from cache: " + saved_report_path)
                try:
                    with open(saved_report_path, "rb") as s:
                        report = pickle.load(s)
                        report.logger = logging.getLogger()
                    
                    if report:
                        self.__dict__.update(report.__dict__)
                        return True
                except Exception:
                    self.logger.exception("Unable to unpickle sandbox report: " + saved_report_path)
        return False

    # Function to save this report to the sandbox cache.
    def save_to_cache(self):
        if self.cache_path:
            report_md5 = self.md5_file_path(self.json_path)
            saved_report_path = os.path.join(self.cache_path, report_md5)
            self.logger.debug("Saving sandbox report to cache: " + saved_report_path)

            try:
                with open(saved_report_path, "wb") as p:
                    pickle.dump(self, p)
            except Exception:
                self.logger.exception("Unable to pickle sandbox report: " + saved_report_path)

    # Function to get the MD5 of a file path. Currently used
    # to build the filename of cached reports.
    def md5_file_path(self, file_path):
        if os.path.exists(file_path) and os.path.isfile(file_path):
            hasher = hashlib.md5()
            with open(file_path, "rb") as f:
                buffer = f.read()
                hasher.update(buffer)
                
            return hasher.hexdigest()
        else:
            return ""
        
    # Function to load and return the report's JSON.
    def load_json(self, json_path):
        with open(json_path) as j:
            return json.load(j)

    # Generic function used to parse JSON keys.
    def parse(self, json_dict, *json_keys, error=""):
        for key in json_keys:
            try:
                json_dict = json_dict[key]
            except KeyError:
                return error
            except TypeError:
                return error
        return json_dict

    def parse_json_urls(self):
        self.logger.debug("Looking for URLs in the JSON report")
        json_urls = []

        if self.report:
            json_urls = RegexHelpers.find_urls(str(self.report))

        json_urls = list(set(json_urls))
        return json_urls
    
    def get_all_urls(self):
        all_urls = []
        #all_urls += list(self.json_urls)
        all_urls += list(self.process_tree_urls)
        all_urls += list(self.memory_urls)
        all_urls += list(self.strings_urls)
        for request in self.http_requests:
            url = "http://" + request.host + request.uri
            if RegexHelpers.is_url(url):
                all_urls.append(url)

        return sorted(list(set(all_urls)))
        
    
    # Build a list of Indicators from the report.
    def extract_indicators(self, check_whitelist=False):
        # Make an Indicator for the sample's MD5 hash.
        if RegexHelpers.is_md5(self.md5):
            try:
                ind = Indicator.Indicator(self.md5, "Hash - MD5")
                ind.add_tags("sandboxed_sample")
                self.iocs.append(ind)
            except ValueError:
                pass
        
        # Make an Indicator for the sample's SHA1 hash.
        if RegexHelpers.is_sha1(self.sha1):
            try:
                ind = Indicator.Indicator(self.sha1, "Hash - SHA1")
                ind.add_tags("sandboxed_sample")
                self.iocs.append(ind)
            except ValueError:
                pass
            
        # Make an Indicator for the sample's SHA256 hash.
        if RegexHelpers.is_sha256(self.sha256):
            try:
                ind = Indicator.Indicator(self.sha256, "Hash - SHA256")
                ind.add_tags("sandboxed_sample")
                self.iocs.append(ind)
            except ValueError:
                pass
            
        # Make Indicators for any contacted hosts.
        for host in self.contacted_hosts:
            # Make an Indicator for the IP itself.
            if RegexHelpers.is_ip(host.ipv4):
                try:
                    ind = Indicator.Indicator(host.ipv4, "Address - ipv4-addr")
                    ind.add_tags("contacted_host")
                    if self.whitelister.is_tor_node(host.ipv4):
                        ind.add_tags("tor_node")
                    if host.protocol and host.port:
                        ind.add_tags(host.protocol + " " + host.port)
                    elif host.protocol and not host.port:
                        ind.add_tag(host.protocol)
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
        for file in self.dropped_files:
            # Make an Indicator for the file path.
            try:
                ind = Indicator.Indicator(file.path, "Windows - FilePath")
                ind.add_tags("dropped_file")
                ind.add_relationships(file.filename)
                self.iocs.append(ind)
            except ValueError:
                pass

            # Make an Indicator for the file name.
            try:
                ind = Indicator.Indicator(file.filename, "Windows - FileName")
                ind.add_tags("dropped_file")
                ind.add_relationships([file.path, file.md5, file.sha1, file.sha256])
                self.iocs.append(ind)
            except ValueError:
                pass

            # Make an Indicator for the MD5 hash.
            if RegexHelpers.is_md5(file.md5):
                try:
                    ind = Indicator.Indicator(file.md5, "Hash - MD5")
                    ind.add_tags([file.filename, "dropped_file"])
                    ind.add_relationships([file.filename, file.path, file.sha1, file.sha256])
                    self.iocs.append(ind)
                except ValueError:
                    pass

            # Make an Indicator for the SHA1 hash.
            if RegexHelpers.is_sha1(file.sha1):
                try:
                    ind = Indicator.Indicator(file.sha1, "Hash - SHA1")
                    ind.add_tags([file.filename, "dropped_file"])
                    ind.add_relationships([file.filename, file.path, file.md5, file.sha256])
                    self.iocs.append(ind)
                except ValueError:
                    pass

            # Make an Indicator for the SHA256 hash.
            if RegexHelpers.is_sha256(file.sha256):
                try:
                    ind = Indicator.Indicator(file.sha256, "Hash - SHA256")
                    ind.add_tags([file.filename, "dropped_file"])
                    ind.add_relationships([file.filename, file.path, file.md5, file.sha1])
                    self.iocs.append(ind)
                except ValueError:
                    pass
                    
        # Make Indicators for any HTTP requests.
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
        indicator_list = Indicator.generate_url_indicators(self.memory_urls)

        # Add some extra tags to the generated indicators and
        # then add them to our main IOC list.
        for ind in indicator_list:
            ind.add_tags("url_in_memory")
            self.iocs.append(ind)
                
        # Make Indicators for any URLs found in the sample's strings.
        indicator_list = Indicator.generate_url_indicators(self.strings_urls)

        # Add some extra tags to the generated indicators and
        # then add them to our main IOC list.
        for ind in indicator_list:
            ind.add_tags("url_in_strings")
            self.iocs.append(ind)

        # Make Indicators for any URLs found in the sample's process tree.
        indicator_list = Indicator.generate_url_indicators(self.process_tree_urls)

        # Add some extra tags to the generated indicators and
        # then add them to our main IOC list.
        for ind in indicator_list:
            ind.add_tags("url_in_process_tree")
            self.iocs.append(ind)

        # Make Indicators for any mutexes.
        for mutex in self.mutexes:
            try:
                ind = Indicator.Indicator(mutex, "Windows - Mutex")
                ind.add_tags("mutex_created")
                self.iocs.append(ind)
            except ValueError:
                pass
                
        # Run the IOCs through the whitelists if requested.
        if check_whitelist:
            self.logger.debug("Running whitelists against sandbox report: " + self.sandbox_url)
            self.iocs = Indicator.run_whitelist(self.config, self.iocs)
            
        # Finally merge the IOCs so we don't have any duplicates.
        self.iocs = Indicator.merge_duplicate_indicators(self.iocs)

    # Property getter/setter for each class attribute. Most of these are not
    # actually necessary, but they help keep the data in a consistent format
    # in case you have some other file expecting these values to be a certain way.
    @property
    def sandbox_name(self):
        return self._sandbox_name
    
    @sandbox_name.setter
    def sandbox_name(self, sandbox_name):
        self._sandbox_name = str(sandbox_name)
        
    @property
    def sandbox_display_name(self):
        return self._sandbox_display_name
    
    @sandbox_display_name.setter
    def sandbox_display_name(self, sandbox_display_name):
        self._sandbox_display_name = str(sandbox_display_name)
        
    @property
    def sandbox_url(self):
        return self._sandbox_url
    
    @sandbox_url.setter
    def sandbox_url(self, sandbox_url):
        self._sandbox_url = str(sandbox_url)
        
    @property
    def screenshot_url(self):
        return self._screenshot_url
    
    @screenshot_url.setter
    def screenshot_url(self, screenshot_url):
        self._screenshot_url = str(screenshot_url)
        
    @property
    def filename(self):
        return self._filename
    
    @filename.setter
    def filename(self, filename):
        self._filename = str(filename)

    @property
    def md5(self):
        return self._md5
    
    @md5.setter
    def md5(self, md5):
        if RegexHelpers.is_md5(str(md5)):
            self._md5 = str(md5)
        else:
            self._md5 = ""
            
    @property
    def sha1(self):
        return self._sha1
    
    @sha1.setter
    def sha1(self, sha1):
        if RegexHelpers.is_sha1(str(sha1)):
            self._sha1 = str(sha1)
        else:
            self._sha1 = ""
            
    @property
    def sha256(self):
        return self._sha256
    
    @sha256.setter
    def sha256(self, sha256):
        if RegexHelpers.is_sha256(str(sha256)):
            self._sha256 = str(sha256)
        else:
            self._sha256 = ""
            
    @property
    def sha512(self):
        return self._sha512
    
    @sha512.setter
    def sha512(self, sha512):
        if RegexHelpers.is_sha512(str(sha512)):
            self._sha512 = str(sha512)
        else:
            self._sha512 = ""
            
    @property
    def ssdeep(self):
        return self._ssdeep
    
    @ssdeep.setter
    def ssdeep(self, ssdeep):
        self._ssdeep = str(ssdeep)
        
    @property
    def malware_family(self):
        return self._malware_family
    
    @malware_family.setter
    def malware_family(self, malware_family):
        self._malware_family = str(malware_family)
        
    @property
    def contacted_hosts(self):
        return self._contacted_hosts
    
    @contacted_hosts.setter
    def contacted_hosts(self, contacted_hosts):
        self._contacted_hosts = []
        
        try:
            for host in contacted_hosts:
                if isinstance(host, ContactedHost):
                    host.associated_domains_string = ""
                    for domain in host.associated_domains:
                        host.associated_domains_string += domain["domain"] + " (" + domain["date"] + ") "
                    self._contacted_hosts.append(host)
        except TypeError:
            pass
        
    @property
    def dropped_files(self):
        return self._dropped_files
    
    @dropped_files.setter
    def dropped_files(self, dropped_files):
        self._dropped_files = []
        
        # Check if there are any dropped file restrictions in the config.
        dropped_file_names = []
        if "dropped_file_names" in self.config["BaseSandboxParser"]:
            dropped_file_names = self.config["BaseSandboxParser"]["dropped_file_names"].split(",")

        dropped_file_types = []
        if "dropped_file_types" in self.config["BaseSandboxParser"]:
            dropped_file_types = self.config["BaseSandboxParser"]["dropped_file_types"].split(",")

        try:
            for file in dropped_files:
                if isinstance(file, DroppedFile):
                    # If there are file name restrictions, check if this file matches.
                    if dropped_file_names:
                        if any(name in file.filename for name in dropped_file_names):
                            if file.md5:
                                if not file in self._dropped_files:
                                    self._dropped_files.append(file)
                            else:
                                # Append the dropped file if there is not already one with the same name.
                                if not any(file.filename == unique_dropped_file.filename for unique_dropped_file in self._dropped_files):
                                    self._dropped_files.append(file)

                    # If there are any file type restrictions, check if this file matches.
                    if dropped_file_types:
                        if any(t in file.type for t in dropped_file_types):
                            if file.md5:
                                if not file in self._dropped_files:
                                    self._dropped_files.append(file)
                            else:
                                # Append the dropped file if there is not already one with the same name.
                                if not any(file.filename == unique_dropped_file.filename for unique_dropped_file in self._dropped_files):
                                    self._dropped_files.append(file)

        except TypeError:
            pass
        
    @property
    def http_requests(self):
        return self._http_requests
    
    @http_requests.setter
    def http_requests(self, http_requests):
        self._http_requests = []
        
        try:
            for request in http_requests:
                if isinstance(request, HttpRequest):
                    url = "http://" + request.host + request.uri
                    self._http_requests.append(request)
        except TypeError:
            pass
        
    @property
    def dns_requests(self):
        return self._dns_requests
    
    @dns_requests.setter
    def dns_requests(self, dns_requests):
        self._dns_requests = []
        
        try:
            for request in dns_requests:
                if isinstance(request, DnsRequest):
                    if RegexHelpers.is_ip(request.answer):
                        self._dns_requests.append(request)
                    elif RegexHelpers.is_domain(request.answer):
                        self._dns_requests.append(request)
        except TypeError:
            pass
        
    @property
    def process_tree(self):
        return self._process_tree
    
    @process_tree.setter
    def process_tree(self, process_tree):
        self._process_tree = []
        
        if isinstance(process_tree, ProcessList):
            self._process_tree = process_tree
            
    @property
    def process_tree_urls(self):
        return self._process_tree_urls
    
    @process_tree_urls.setter
    def process_tree_urls(self, process_tree_urls):
        self._process_tree_urls = []
        
        # If we were given a single string, add that.
        if RegexHelpers.is_url(str(process_tree_urls)):
            self._process_tree_urls.append(str(process_tree_urls))
        # Otherwise, try and process it like a list or set.
        else:
            try:
                for url in process_tree_urls:
                    if RegexHelpers.is_url(str(url)):
                        self._process_tree_urls.append(str(url))
            except TypeError:
                pass
            
    @property
    def strings(self):
        return self._strings
    
    @strings.setter
    def strings(self, strings):
        self._strings = []
        
        # If we were given a single string, add that.
        if isinstance(strings, str):
            self._strings.append(strings)
        # Otherwise, try and process it like a list or set.
        else:
            try:
                for string in strings:
                    if isinstance(string, str):
                        self._strings.append(string)
            except TypeError:
                pass
            
    @property
    def strings_urls(self):
        return self._strings_urls
    
    @strings_urls.setter
    def strings_urls(self, strings_urls):
        self._strings_urls = []
        
        # If we were given a single string, add that.
        if RegexHelpers.is_url(str(strings_urls)):
            self._strings_urls.append(str(strings_urls))
        # Otherwise, try and process it like a list or set.
        else:
            try:
                for url in strings_urls:
                    if RegexHelpers.is_url(str(url)):
                        self._strings_urls.append(str(url))
            except TypeError:
                pass
            
    @property
    def memory_urls(self):
        return self._memory_urls
    
    @memory_urls.setter
    def memory_urls(self, memory_urls):
        self._memory_urls = []
        
        # If we were given a single string, add that.
        if RegexHelpers.is_url(str(memory_urls)):
            self._memory_urls.append(str(memory_urls))
        # Otherwise, try and process it like a list or set.
        else:
            try:
                for url in memory_urls:
                    if RegexHelpers.is_url(str(url)):
                        self._memory_urls.append(str(url))
            except TypeError:
                pass
            
    @property
    def mutexes(self):
        return self._mutexes
    
    @mutexes.setter
    def mutexes(self, mutexes):
        self._mutexes = []
        
        # If we were given a single string, add that.
        if isinstance(mutexes, str):
            self._mutexes.append(mutexes)
        # Otherwise, try and process it like a list or set.
        else:
            try:
                for mutex in mutexes:
                    if isinstance(mutex, str):
                        self._mutexes.append(mutex)
            except TypeError:
                pass
            
    @property
    def resolved_apis(self):
        return self._resolved_apis
    
    @resolved_apis.setter
    def resolved_apis(self, resolved_apis):
        self._resolved_apis = []
        
        # If we were given a single string, add that.
        if isinstance(resolved_apis, str):
            self._resolved_apis.append(resolved_apis)
        # Otherwise, try and process it like a list or set.
        else:
            try:
                for api in resolved_apis:
                    if isinstance(api, str):
                        self._resolved_apis.append(api)
            except TypeError:
                pass
            
    @property
    def created_services(self):
        return self._created_services
    
    @created_services.setter
    def created_services(self, created_services):
        self._created_services = []
        
        # If we were given a single string, add that.
        if isinstance(created_services, str):
            self._created_services.append(created_services)
        # Otherwise, try and process it like a list or set.
        else:
            try:
                for service in created_services:
                    if isinstance(service, str):
                        self._created_services.append(service)
            except TypeError:
                pass
            
    @property
    def started_services(self):
        return self._started_services
    
    @started_services.setter
    def started_services(self, started_services):
        self._started_services = []
        
        # If we were given a single string, add that.
        if isinstance(started_services, str):
            self._started_services.append(started_services)
        # Otherwise, try and process it like a list or set.
        else:
            try:
                for service in started_services:
                    if isinstance(service, str):
                        self._started_services.append(service)
            except TypeError:
                pass
            
    @property
    def iocs(self):
        return self._iocs
    
    @iocs.setter
    def iocs(self, iocs):
        self._iocs = []
        
        # If we were given a single Indicator, add that.
        if not isinstance(iocs, list) and not isinstance(iocs, set):
            self._iocs.append(iocs)
        # Otherwise, try and process it like a list or set.
        else:
            try:
                for ioc in iocs:
                    self._iocs.append(ioc)
            except TypeError:
                pass

# Function that takes a list of BaseSandboxParser sub-classes and
# balls them all up into a single report with deduped attributes
# (for example it will dedup all of the HTTP requests from the reports).
def dedup_reports(config, report_list, whitelister=None):
    logger = logging.getLogger()
    logger.debug("Deduping sandbox report list")

    dedup_report = BaseSandboxParser(config, whitelister=whitelister)
    dedup_report.filename = "Unknown Filename"
    dedup_report.process_tree_list = []

    for report in report_list:
        # Check if the filename is set and it is not WildFire's "sample".
        if report.filename and report.filename != "sample":
            dedup_report.filename = report.filename

        if report.md5:
            dedup_report.md5 = report.md5

        if report.sha1:
            dedup_report.sha1 = report.sha1

        if report.sha256:
            dedup_report.sha256 = report.sha256

        if report.sha512:
            dedup_report.sha512 = report.sha512

        if report.ssdeep:
            dedup_report.ssdeep = report.ssdeep

        if report.malware_family:
            dedup_report.malware_family = report.malware_family

        # Dedup the IOCs.
        for ioc in report.iocs:
            if ioc not in dedup_report.iocs:
                dedup_report.iocs.append(ioc)
            
        # Dedup the contacted hosts.
        for host in report.contacted_hosts:
            if host not in dedup_report.contacted_hosts:
                if whitelister:
                    if not whitelister.is_ip_whitelisted(host.ipv4):
                        dedup_report.contacted_hosts.append(host)
                else:
                    dedup_report.contacted_hosts.append(host)

        # Dedup the dropped files.
        for file in report.dropped_files:
            if file not in dedup_report.dropped_files:
                if whitelister:
                    if not whitelister.is_file_path_whitelisted(file.path):
                        if not whitelister.is_file_name_whitelisted(file.filename):
                            logger.debug("Adding non-whitelisted dropped file: " + file.filename + " " + file.md5)
                            dedup_report.dropped_files.append(file)
                        else:
                            logger.debug("Skipping whitelisted dropped file name: " + file.filename)
                    else:
                        logger.debug("Skipping whitelisted dropped file path: " + file.path)
                else:
                    logger.debug("Adding dropped file: " + file.filename + " " + file.md5)
                    dedup_report.dropped_files.append(file)
            else:
                logger.debug("Dropped file already in dedup list: " + file.filename + " " + file.md5)

        # Dedup the HTTP requests.
        for request in report.http_requests:
            if request not in dedup_report.http_requests:
                if whitelister:
                    if RegexHelpers.is_ip(request.host):
                        if not whitelister.is_ip_whitelisted(request.host):
                            dedup_report.http_requests.append(request)
                    else:
                        if not whitelister.is_domain_whitelisted(request.host):
                            dedup_report.http_requests.append(request)
                else:
                    dedup_report.http_requests.append(request)

        # Dedup the DNS requests.
        for request in report.dns_requests:
            if request not in dedup_report.dns_requests:
                if whitelister:
                    if not whitelister.is_domain_whitelisted(request.request):
                        if RegexHelpers.is_ip(request.answer):
                            if not whitelister.is_ip_whitelisted(request.answer):
                                dedup_report.dns_requests.append(request)
                        else:
                            if not whitelister.is_domain_whitelisted(request.answer):
                                dedup_report.dns_requests.append(request)
                else:
                    dedup_report.dns_requests.append(request)

        # Dedup the process tree URLs.
        for url in report.process_tree_urls:
            if url not in dedup_report.process_tree_urls:
                if whitelister:
                    if not whitelister.is_url_whitelisted(url):
                        dedup_report.process_tree_urls.append(url)
                else:
                    dedup_report.process_tree_urls.append(url)

        # Dedup the memory URLs.
        for url in report.memory_urls:
            if url not in dedup_report.memory_urls:
                if whitelister:
                    if not whitelister.is_url_whitelisted(url):
                        dedup_report.memory_urls.append(url)
                else:
                    dedup_report.memory_urls.append(url)

        # Dedup the strings URLs.
        for url in report.strings_urls:
            if url not in dedup_report.strings_urls:
                if whitelister:
                    if not whitelister.is_url_whitelisted(url):
                        dedup_report.strings_urls.append(url)
                else:
                    dedup_report.strings_urls.append(url)

        # Dedup the mutexes.
        for mutex in report.mutexes:
            if mutex not in dedup_report.mutexes:
                if whitelister:
                    if not whitelister.is_mutex_whitelisted(mutex):
                        dedup_report.mutexes.append(mutex)
                else:
                    dedup_report.mutexes.append(mutex)

        # Dedup the resolved APIs.
        for api in report.resolved_apis:
            if api not in dedup_report.resolved_apis:
                dedup_report.resolved_apis.append(api)

        # Dedup the created services.
        for service in report.created_services:
            if service not in dedup_report.created_services:
                dedup_report.created_services.append(service)

        # Dedup the started services.
        for service in report.started_services:
            if service not in dedup_report.started_services:
                dedup_report.started_services.append(service)

        # Finally, just add the process tree as-is.
        dedup_report.process_tree_list.append(str(report.process_tree))

    return dedup_report
    
# These are "standard" versions of various things a sandbox
# report might have. They help to access and display the
# sandbox report data in a consisent manor.
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
        return hash(self.filename+self.md5)
    
    def __eq__(self, other):
        if isinstance(other, DroppedFile):
            return self.md5 == other.md5
            #if self.md5 and other.md5:
            #    return self.md5 == other.md5
            #else:
            #    if self.filename == other.filename:
            #        self.merge_dropped_file(other)
            #
            #    return self.filename == other.filename
        else:
            return False

    def merge_dropped_file(self, other):
        if isinstance(other, DroppedFile):
            if not self.filename:
                self.filename = other.filename
            if not self.path:
                self.path = other.path
            if not self.os_path:
                self.os_path = other.os_path
            if not self.size:
                self.size = other.size
            if not self.type:
                self.type = other.type
            if not self.md5:
                self.md5 = other.md5
            if not self.sha1:
                self.sha1 = other.sha1
            if not self.sha256:
                self.sha256 = other.sha256
            if not self.sha512:
                self.sha512 = other.sha512
            if not self.ssdeep:
                self.ssdeep = other.ssdeep

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
