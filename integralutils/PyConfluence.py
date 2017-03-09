import os
import configparser
import json
import requests
import re

class PyConfluence():
    def __init__(self, api_url=None, space_key=None, config_path=None, requests_verify=True, debug=False):
        # If we weren't given a config_path, assume we're loading
        # the one shipped with integralutils.
        if not config_path:
            config_path = os.path.join(os.path.dirname(__file__), "etc", "config.ini")
            
        config = configparser.ConfigParser()
        config.read(config_path)
        
        # First check if there is a custom CA cert to use.
        if "ca_cert" in config["Requests"]:
            self.requests_verify = config["Requests"]["ca_cert"]
        else:
            self.requests_verify = requests_verify

        # Load the API URL and space key from the config if we need to.
        if not api_url:
            self.api_url = config["PyConfluence"]["api_url"]
        else:
            self.api_url = api_url
        
        if not space_key:
            self.space_key = config["PyConfluence"]["space_key"]
        else:
            self.space_key = space_key
        
        # Load the login credentials.
        credential_file = config["PyConfluence"]["credentials"]
        
        if "~" in credential_file:
            home_directory = os.path.expanduser("~")
            credential_file = credential_file.replace("~", home_directory)

        if not os.path.isfile(credential_file):
            raise FileNotFoundError('You do not have your Confluence credentials saved at: ' + credential_file)
        else:
            # Verify the creds file has the proper permissions.
            perms = oct(os.stat(credential_file).st_mode & 0o777)
            if perms == "0o600":
                with open(credential_file) as c:
                    self.username = c.readline().strip()
                    self.password = c.readline().strip()
            else:
                raise PermissionError("Your Confluence credentials file should have 600 permissions!")
        
        if debug == True:
            self.debug = True
        else:
            self.debug = False
            
        self._cached_page = None
        
    def does_attachment_exist(self, page_title, filename):
        page_id = self.get_page_id(page_title)
        params = {'filename': filename, 'expand': 'container,version', 'spaceKey': self.space_key}
        r = requests.get(self.api_url + "/" + page_id + "/child/attachment", auth=(self.username, self.password), params=params, verify=self.requests_verify)
        
        if self._validate_request(r, error_msg="Error with does_attachment_exist Confluence API query."):
            j = json.loads(r.text)
            if j["results"]:
                return True
            else:
                return False
        
    def attach_file(self, page_title, file_path):
        page_id = self.get_page_id(page_title)
        if os.path.exists(file_path):
            attachment = {"file": open(file_path, "rb")}
            r = requests.post(self.api_url + "/" + page_id + "/child/attachment", auth=(self.username, self.password), files=attachment, headers=({'X-Atlassian-Token':'nocheck'}), verify=self.requests_verify)
            if self._validate_request(r, error_msg="Unable to upload attachment '" + file_path + "'."):
                return True
            else:
                return False
            
    def get_attachment_id(self, page_title, attachment_name):
        page_id = self.get_page_id(page_title)
        params = {'filename': attachment_name, 'expand': 'container,version', 'spaceKey': self.space_key}
        r = requests.get(self.api_url + "/" + page_id + "/child/attachment", auth=(self.username, self.password), params=params, verify=self.requests_verify)
        
        if self._validate_request(r, error_msg="Error with does_attachment_exist Confluence API query."):
            j = json.loads(r.text)
            if j["results"]:
                return (j["results"][0]["id"].replace("att", ""))
            else:
                return False
            
    def get_page_id(self, page_title):
        if not self._cached_page:
            if self.debug:
                print("get_page_id caching page.")
            self._cache_this_page(page_title)
        else:
            if page_title != self._cached_page["results"][0]["title"]:
                if self.debug:
                    print("get_page_id caching new page.")
                self._cache_this_page(page_title)
        return str(self._cached_page["results"][0]["id"])

    def get_page_version(self, page_title):
        if not self._cached_page:
            if self.debug:
                print("get_page_version caching page.")
            self._cache_this_page(page_title)
        else:
            if page_title != self._cached_page["results"][0]["title"]:
                if self.debug:
                    print("get_page_version caching new page.")
                self._cache_this_page(page_title)
        return self._cached_page["results"][0]["version"]["number"]

    # Don't forget to re-cache the page.
    def create_page(self, page_title, page_text, parent_title=None):
        if not self.does_page_exist(page_title):
            if parent_title and self.does_page_exist(parent_title):
                parent_id = self.get_page_id(parent_title)
                data = {'type': 'page', 'title': page_title, 'space': {'key': self.space_key}, "ancestors": [{"id": parent_id}], 'body': {'storage': {'value': page_text, 'representation': 'storage'}}}
            else:
                data = {'type': 'page', 'title': page_title, 'space': {'key': self.space_key}, 'body': {'storage': {'value': page_text, 'representation': 'storage'}}}
            r = requests.post(self.api_url, auth=(self.username, self.password), data=json.dumps(data), headers=({'Content-Type':'application/json'}), verify=self.requests_verify)
            if self._validate_request(r, error_msg="Unable to create page '" + page_title + "'."):
                if self.debug:
                    print("create_page updating cached page.")
                self._cache_this_page(page_title)
                return True
            else:
                self._cached_page = None
                return False
                
    # Adding a label does not increase the page version, so no need to re-cache the page.
    def add_page_label(self, page_title, label):
        if self.does_page_exist(page_title):
            page_id = self.get_page_id(page_title)
            data = [{"prefix": "global", "name": label}]
            r = requests.post(self.api_url + "/" + page_id + "/label", auth=(self.username, self.password), data=json.dumps(data), headers=({'Content-Type':'application/json'}), verify=self.requests_verify)
            if self._validate_request(r, error_msg="Error with add_page_label Confluence API query."):
                return True
            else:
                return False

    # This updates the cached page. Need to call "commit_page" to update the real thing.
    def update_page(self, page_title, page_text):
        if not self._cached_page:
            if self.debug:
                print("update_page caching page.")
            self._cache_this_page(page_title)
        else:
            if page_title != self._cached_page["results"][0]["title"]:
                if self.debug:
                    print("update_page caching new page.")
                self._cache_this_page(page_title)
        
        self._cached_page["results"][0]["body"]["storage"]["value"] = page_text

    # Don't forget to update the cached page.
    def commit_page(self, page_title):
        if self._cached_page and page_title == self._cached_page["results"][0]["title"]:
            page_id = self.get_page_id(page_title)
            page_current_version = self.get_page_version(page_title)
            cached_page_text = self.get_page_text(page_title)
            if page_id and page_current_version:
                data = {'type': 'page', 'id': page_id, 'title': page_title, 'space': {'key': self.space_key}, 'body': {'storage': {'value': cached_page_text, 'representation': 'storage'}}, 'version': {'number': page_current_version+1}}
                r = requests.put(self.api_url + "/" + page_id, auth=(self.username, self.password), data=json.dumps(data), headers=({'Content-Type':'application/json'}), verify=self.requests_verify)
                if self._validate_request(r, error_msg="Error with commit_page Confluence API query."):
                    if self.debug:
                        print("commit_page updating cached page.")
                    self._cache_this_page(page_title)
                    return True
                else:
                    self._cached_page = None
                    return False

    # This updates the cached page. Need to call "commit_page" to update the real thing.
    def update_section(self, page_title, section_id, section_text):
        if self.does_page_exist(page_title):
            page_id = self.get_page_id(page_title)
            page_current_version = self.get_page_version(page_title)
            if page_id and page_current_version:
                existing_page_text = self.get_page_text(page_title)
                existing_section_text_full = self.get_section_text_full(page_title, section_id)
                existing_section_body = self.get_section_text_body(page_title, section_id)
                
                if not existing_section_body:
                    new_section_text = existing_section_text_full.replace("</ac:rich-text-body>", section_text + "</ac:rich-text-body>")
                else:
                    new_section_text = existing_section_text_full.replace(existing_section_body, section_text)
                
                new_page_text = existing_page_text.replace(existing_section_text_full, new_section_text)

                if self.update_page(page_title, new_page_text):
                    return True
                else:
                    return False

    def get_section_text_full(self, page_title, section_id):
        page_text = self.get_page_text(page_title)
        
        if page_text:
            section_pattern = re.compile(r'(<ac:structured-macro ac:name="section" ac:schema-version="1" ac:macro-id="'+section_id+'">.*?</ac:rich-text-body></ac:structured-macro>)', re.DOTALL)
            results = section_pattern.search(page_text)
            if results:
                section_text = results.group(1)
                return section_text
            else:
                raise ValueError("Unable to get section text for section '" + section_id + "'.")
        else:
            raise ValueError("Unable to get page text for page '" + page_title + "'.")
        
    def get_section_text_body(self, page_title, section_id):
        section_text = self.get_section_text_full(page_title, section_id)
        
        if section_text:
            section_body_pattern = re.compile(r'<ac:rich-text-body><h[1-7]>.*?</h[1-7]>(.*?)</ac:rich-text-body>', re.DOTALL)
            results = section_body_pattern.search(section_text)
            if results:
                section_body = results.group(1)
                return section_body
            else:
                raise ValueError("Unable to get section body for section '" + section_id + "'.")

    def does_page_exist(self, page_title):
        if not self._cached_page:
            if self.debug:
                print("does_page_exist caching page.")
            try:
                self._cache_this_page(page_title)
            except ValueError:
                self._cached_page = None
                return False
        else:
            if page_title != self._cached_page["results"][0]["title"]:
                if self.debug:
                    print("does_page_exist caching new page.")
                try:
                    self._cache_this_page(page_title)
                except ValueError:
                    self._cached_page = None
                    return False
        return True

    def get_page_text(self, page_title):
        if not self._cached_page:
            if self.debug:
                print("get_page_text caching page.")
            self._cache_this_page(page_title)
        else:
            if page_title != self._cached_page["results"][0]["title"]:
                if self.debug:
                    print("get_page_text caching new page.")
                self._cache_this_page(page_title)
        return self._cached_page["results"][0]["body"]["storage"]["value"]

    def _cache_this_page(self, page_title):
        params = {'title': page_title, 'expand': 'body.storage,version', 'spaceKey': self.space_key}
        r = requests.get(self.api_url, auth=(self.username, self.password), params=params, verify=self.requests_verify)
        
        if self._validate_request(r, error_msg="Error with _cache_this_page Confluence API query."):
            j = json.loads(r.text)
            if j["results"]:
                self._cached_page = j
                if self.debug:
                    print("Cached Confluence page '" + page_title + "'.")
            else:
                raise ValueError("Page '" + page_title + "' does not exist.")

    def _validate_request(self, request, error_msg='There was an error with the query.'):
        if request.status_code == 200:
            return True
        else:
            if self.debug:
                print(request.text)
            raise ValueError(error_msg)

