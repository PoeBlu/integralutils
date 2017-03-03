import os
import re
import configparser

class Whitelist:
    def __init__(self, config_path=None):
        # If we weren't given a config_path, assume we're loading
        # the one shipped with integralutils.
        if not config_path:
            config_path = os.path.join(os.path.dirname(__file__), "etc", "whitelist.ini")

        self.config = configparser.ConfigParser()
        self.config.read(config_path)

        # This will read your config file and create class variables
        # named <section>_<key>. For example, if your config file has
        # a section named "whitelist" and a key in that section named
        # "ip" with a path to your IP whitelist file, this code will
        # read that file, create a list out of its lines, and assign it
        # to a variable as self.whitelist_ip.
        for section in self.config.sections():
            for key in self.config[section]:
                section_key = section + "_" + key
                if not hasattr(self, section_key):
                    # I removed a try/except block around this since users will
                    # probably want to see the FileNotFoundError if their whitelist
                    # config points to a missing whitelist.
                    with open(self.config[section][key]) as f:
                        lines = f.read().splitlines()
                        
                        # Remove any lines that begin with #.
                        lines = [line for line in lines if not line.startswith("#")]
                        
                        # Remove any blank lines.
                        lines = [line for line in lines if line]

                        # Store the lines list at self.<section>_<key>
                        setattr(self, section_key, lines)

    def is_ip_whitelisted(self, ip):
        if hasattr(self, "whitelist_ip"):
            for regex in self.whitelist_ip:
                pattern = re.compile(regex)
                if pattern.search(ip):
                    return True
            else:
                return False
        else:
            return False
        
    def is_ip_benign(self, ip):
        if hasattr(self, "benignlist_ip"):
            for regex in self.benignlist_ip:
                pattern = re.compile(regex)
                if pattern.search(ip):
                    return True
            else:
                return False
        else:
            return False
        
    def is_domain_whitelisted(self, domain):
        if hasattr(self, "whitelist_domain"):
            for regex in self.whitelist_domain:
                pattern = re.compile(regex)
                if pattern.search(domain):
                    return True
            else:
                return False
        else:
            return False
        
    def is_domain_benign(self, domain):
        if hasattr(self, "benignlist_domain"):
            for regex in self.benignlist_domain:
                pattern = re.compile(regex)
                if pattern.search(domain):
                    return True
            else:
                return False
        else:
            return False
        
    def is_file_path_whitelisted(self, file_path):
        if hasattr(self, "whitelist_filepath"):
            for regex in self.whitelist_filepath:
                pattern = re.compile(regex)
                if pattern.search(file_path):
                    return True
            else:
                return False
        else:
            return False
        
    def is_file_path_benign(self, file_path):
        if hasattr(self, "benignlist_filepath"):
            for regex in self.benignlist_filepath:
                pattern = re.compile(regex)
                if pattern.search(file_path):
                    return True
            else:
                return False
        else:
            return False
        
    def is_file_name_whitelisted(self, file_name):
        if hasattr(self, "whitelist_filename"):
            for regex in self.whitelist_filename:
                pattern = re.compile(regex)
                if pattern.search(file_name):
                    return True
            else:
                return False
        else:
            return False
        
    def is_file_name_benign(self, file_name):
        if hasattr(self, "benignlist_filename"):
            for regex in self.benignlist_filename:
                pattern = re.compile(regex)
                if pattern.search(file_name):
                    return True
            else:
                return False
        else:
            return False
        
    def is_email_whitelisted(self, email):
        if hasattr(self, "whitelist_email"):
            for regex in self.whitelist_email:
                pattern = re.compile(regex)
                if pattern.search(email):
                    return True
            else:
                return False
        else:
            return False
        
    def is_email_benign(self, email):
        if hasattr(self, "benignlist_email"):
            for regex in self.benignlist_email:
                pattern = re.compile(regex)
                if pattern.search(email):
                    return True
            else:
                return False
        else:
            return False
        
    def is_md5_whitelisted(self, md5):
        if hasattr(self, "whitelist_md5"):
            for regex in self.whitelist_md5:
                pattern = re.compile(regex)
                if pattern.search(md5):
                    return True
            else:
                return False
        else:
            return False

    def is_md5_benign(self, md5):
        if hasattr(self, "benignlist_md5"):
            for regex in self.benignlist_md5:
                pattern = re.compile(regex)
                if pattern.search(md5):
                    return True
            else:
                return False
        else:
            return False
        
    def is_sha1_whitelisted(self, sha1):
        if hasattr(self, "whitelist_sha1"):
            for regex in self.whitelist_sha1:
                pattern = re.compile(regex)
                if pattern.search(sha1):
                    return True
            else:
                return False
        else:
            return False

    def is_sha1_benign(self, sha1):
        if hasattr(self, "benignlist_sha1"):
            for regex in self.benignlist_sha1:
                pattern = re.compile(regex)
                if pattern.search(sha1):
                    return True
            else:
                return False
        else:
            return False
        
    def is_sha256_whitelisted(self, sha256):
        if hasattr(self, "whitelist_sha256"):
            for regex in self.whitelist_sha256:
                pattern = re.compile(regex)
                if pattern.search(sha256):
                    return True
            else:
                return False
        else:
            return False

    def is_sha256_benign(self, sha256):
        if hasattr(self, "benignlist_sha256"):
            for regex in self.benignlist_sha256:
                pattern = re.compile(regex)
                if pattern.search(sha256):
                    return True
            else:
                return False
        else:
            return False
        
    def is_registry_whitelisted(self, reg_key):
        if hasattr(self, "whitelist_registry"):
            for regex in self.whitelist_registry:
                pattern = re.compile(regex)
                if pattern.search(reg_key):
                    return True
            else:
                return False
        else:
            return False

    def is_registry_benign(self, reg_key):
        if hasattr(self, "benignlist_registry"):
            for regex in self.benignlist_registry:
                pattern = re.compile(regex)
                if pattern.search(reg_key):
                    return True
            else:
                return False
        else:
            return False
        
    def is_url_whitelisted(self, url):
        if hasattr(self, "whitelist_url"):
            for regex in self.whitelist_url:
                pattern = re.compile(regex)
                if pattern.search(url):
                    return True
            else:
                return False
        else:
            return False

    def is_url_benign(self, url):
        if hasattr(self, "benignlist_url"):
            for regex in self.benignlist_url:
                pattern = re.compile(regex)
                if pattern.search(url):
                    return True
            else:
                return False
        else:
            return False
        
    def is_mutex_whitelisted(self, mutex):
        if hasattr(self, "whitelist_mutex"):
            for regex in self.whitelist_mutex:
                pattern = re.compile(regex)
                if pattern.search(mutex):
                    return True
            else:
                return False
        else:
            return False

    def is_mutex_benign(self, mutex):
        if hasattr(self, "benignlist_mutex"):
            for regex in self.benignlist_mutex:
                pattern = re.compile(regex)
                if pattern.search(mutex):
                    return True
            else:
                return False
        else:
            return False
        
    def is_thing_whitelisted(self, thing):
        return(self.is_ip_whitelisted(thing) or
               self.is_domain_whitelisted(thing) or
               self.is_file_path_whitelisted(thing) or
               self.is_file_name_whitelisted(thing) or
               self.is_email_whitelisted(thing) or
               self.is_md5_whitelisted(thing) or
               self.is_sha1_whitelisted(thing) or
               self.is_sha256_whitelisted(thing) or
               self.is_registry_whitelisted(thing) or
               self.is_url_whitelisted(thing) or
               self.is_mutex_whitelisted(thing))
    
    def is_thing_benign(self, thing):
        return(self.is_ip_benign(thing) or
               self.is_domain_benign(thing) or
               self.is_file_path_benign(thing) or
               self.is_file_name_benign(thing) or
               self.is_email_benign(thing) or
               self.is_md5_benign(thing) or
               self.is_sha1_benign(thing) or
               self.is_sha256_benign(thing) or
               self.is_registry_benign(thing) or
               self.is_url_benign(thing) or
               self.is_mutex_benign(thing))