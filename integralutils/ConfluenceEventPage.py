import os
import tempfile
import hashlib

from pymongo import MongoClient
from pymongo.errors import *

from integralutils import BaseSandboxParser
from integralutils import BaseAlert
from integralutils import ACEAlert
from integralutils import Indicator
from integralutils import EmailParser
from integralutils import RegexHelpers
from integralutils.BaseConfluencePage import *

class ConfluenceEventPage(BaseConfluencePage):
    def __init__(self, page_title, parent_title=None, config_path=None):
        # Run the super init to load the config and cache the page if it exists.
        super().__init__(page_title, parent_title=parent_title, config_path=config_path)

        # First check if there is a custom template to use.
        if "template" in self.config["ConfluenceEventPage"]:
            template_path = self.config["ConfluenceEventPage"]["template"]
        # If not, use the one bundled with integralutils.
        else:
            template_path = os.path.join(os.path.dirname(__file__), "etc", "confluence_event_template.txt")
                        
        # If the page does not exist, spin up the template.
        if not self.page_exists():
            self.soup = self.soupify(open(template_path).read())

    def update_time_table(self, times_dict):
        # Get the existing time table and its data.
        existing_time_table = self.get_section("time_table")
        rows = existing_time_table.find_all("tr")
        data = [[td.find_all(text=True) for td in tr.find_all("td")] for tr in rows]

        # Create the parent div tag.
        div = self.new_tag("div")
        
        # Add the header tag.
        header = self.new_tag("h1", parent=div)
        header.string = "Time Table"
        
        # Create a new table tag.
        table = self.new_tag("table", parent=div)
                
        # Loop over the existing table values to build the new table.
        for row in data:
            row_name = "".join(row[0]).replace("  ", " ")
            row_value = "".join(row[1]).replace("  ", " ")
        
            # Loop over the times_dict we were given to see if we need to update this row.
            for time_name in times_dict:
                time_value = times_dict[time_name]
                
                # If this time_name is in the current row_name, update it.
                if time_name in row_name:
                    row_value = time_value
                    
            # Create the table row.
            tr = self.new_tag("tr", parent=table)
            
            # Create the first element in the row.
            td = self.new_tag("td", parent=tr)
            td["class"] = "highlight-red"
            td["data-highlight-colour"] = "red"
            td["style"] = "font-weight: bold"
            td.string = row_name

            # Create the second element in the row.
            td = self.new_tag("td", parent=tr)
            td["class"] = "highlight-red"
            td["data-highlight-colour"] = "red"
            td.string = row_value

        self.update_section(div, old_section_id="time_table")
        
    
    def update_artifacts(self, path, server=None):
        # Create the parent div tag.
        div = self.new_tag("div")
        
        # Add the header tag.
        header = self.new_tag("h2", parent=div)
        header.string = "Artifact Repository"
        
        # If we were given a server name/address, add it first.
        if server:
            server_div = self.new_tag("div", parent=div)
            server_div["style"] = "font-weight: bold"
            server_div.string = server
            
        # Add the path
        path_div = self.new_tag("div", parent=div)
        code = self.new_tag("code", parent=path_div)
        code.string = path
                
        self.update_section(div, old_section_id="artifact_repository")
        
    
    def update_alerts(self, alert_list):
        # Create the parent div tag.
        div = self.new_tag("div")
                
        # Add the header tag.
        header = self.new_tag("h2", parent=div)
        header.string = "Alerts"

        # Create a new table tag.
        table = self.new_tag("table", parent=div)

        # Set up the table header row.
        thead = self.new_tag("thead", parent=table)
        tr = self.new_tag("tr", parent=thead)
        titles = ["URL", "Time", "Description", "Tool", "Type"]
        for title in titles:
            th = self.new_tag("th", parent=tr)
            th.string = title

        # Set up the table body rows.
        tbody = self.new_tag("tbody", parent=table)
        for alert in alert_list:
            if isinstance(alert, BaseAlert.BaseAlert):
                tr = self.new_tag("tr", parent=tbody)

                td = self.new_tag("td", parent=tr)
                url = self.new_tag("a", parent=td)
                url["href"] = alert.alert_url
                url.string = "Alert"

                td = self.new_tag("td", parent=tr)
                td.string = alert.time

                td = self.new_tag("td", parent=tr)
                td.string = alert.description

                td = self.new_tag("td", parent=tr)
                td.string = alert.tool

                td = self.new_tag("td", parent=tr)
                td.string = alert.type
        
        self.update_section(div, old_section_id="alerts")
        
    
    def update_crits_analysis(self, potential_indicators):
        # Create the parent div tag.
        div = self.new_tag("div")
        
        # Continue the section if we were given some potential indicators.
        if potential_indicators:
            # Create the connection to the CRITS Mongo database.
            host = self.config["ConfluenceEventPage"]["crits_mongo_host"]
            port = int(self.config["ConfluenceEventPage"]["crits_mongo_port"])
            
            try:
                client = MongoClient(host, port)
                db = client.crits

                for potential_indicator in potential_indicators:
                    if isinstance(potential_indicator, Indicator.Indicator):
                        # Search CRITS for any Analyzed indicators matching this potential one.
                        crits_indicators = db.indicators.find( { 'status' : 'Analyzed', 'value' : potential_indicator.indicator } )

                        # Only continue if we got back at least 1 indicator.
                        if crits_indicators.count() > 0:
                            div["style"] = "border:1px solid gray;padding:5px;"
                            
                            # Make the section header.
                            header = self.new_tag("h2", parent=div)
                            header.string = "CRITS Analysis"
                            
                            # Set up the pre tag to hold the results.
                            pre = self.new_tag("pre", parent=div)
                            pre.string = ""
                            
                            for crits_indicator in crits_indicators:
                                # Get all of the indicator's unique references.
                                references = set()
                                source_names = set()
                                for source in crits_indicator["source"]:
                                    source_names.add(source["name"])
                                    for instance in source["instances"]:
                                        references.add(instance["reference"])
                                references = sorted(list(references))
                                source_names = sorted(list(source_names))

                                # Only continue if this event's wiki page is not a reference.
                                if not self.get_page_url() in references:
                                    # Extract the values we care about.
                                    ind_value = crits_indicator["value"]
                                    ind_type = crits_indicator["type"]
                                    ind_tags = crits_indicator["bucket_list"]
                                    ind_campaigns = set()
                                    for campaign in crits_indicator["campaign"]:
                                        ind_campaigns.add(campaign["name"])
                                    ind_campaigns = sorted(list(ind_campaigns))

                                    # Add them to the pre's text.
                                    pre.string += ind_type + ": " + ind_value + "\n"
                                    pre.string += "Sources: " + ", ".join(source_names) + "\n"
                                    pre.string += "Campaigns: " + ", ".join(ind_campaigns) + "\n"
                                    pre.string += "Tags: " + ", ".join(ind_tags) + "\n"
                                    
                                    for reference in references:
                                        pre.string += reference + "\n"
                                        
                                    pre.string += "\n"
            except ServerSelectionTimeoutError:
                pass
        
        self.update_section(div, old_section_id="crits_analysis")
        
    
    def update_phish_info(self, email_list):
        # Create the parent div tag.
        div = self.new_tag("div")
        
        # Add the header tag.
        header = self.new_tag("h2", parent=div)
        header.string = "Phish E-mail Information"
        
        # Create a new table tag.
        table = self.new_tag("table", parent=div)
        
        # Set up the table header row.
        thead = self.new_tag("thead", parent=table)
        tr = self.new_tag("tr", parent=thead)
        titles = ["URL", "Time", "From", "To", "Subject", "Attachments", "MD5 Hashes", "CC", "BCC", "Reply-To", "Message ID"]
        for title in titles:
            th = self.new_tag("th", parent=tr)
            th.string = title

        # Set up the table body rows.
        tbody = self.new_tag("tbody", parent=table)
        for email in email_list:
            if isinstance(email, EmailParser.EmailParser):
                tr = self.new_tag("tr", parent=tbody)
                
                td = self.new_tag("td", parent=tr)
                if RegexHelpers.is_url(email.reference):
                    link = self.new_tag("a", parent=td)
                    link["href"] = email.reference
                    link.string = "Alert"

                td = self.new_tag("td", parent=tr)
                td.string = email.received_time
                
                td = self.new_tag("td", parent=tr)
                td.string = email.from_address
                
                td = self.new_tag("td", parent=tr)
                td.string = email.to_string
                
                td = self.new_tag("td", parent=tr)
                if email.decoded_subject:
                    td.string = email.decoded_subject
                else:
                    td.string = email.subject
                
                td = self.new_tag("td", parent=tr)
                td.string = email.attachments_string
                
                td = self.new_tag("td", parent=tr)
                td.string = email.md5_string
                
                td = self.new_tag("td", parent=tr)
                td.string = email.cc_string
                
                td = self.new_tag("td", parent=tr)
                td.string = email.bcc_string
                
                td = self.new_tag("td", parent=tr)
                td.string = email.replyto
                
                td = self.new_tag("td", parent=tr)
                td.string = email.message_id
                
        self.update_section(div, old_section_id="phish_email_information")
        
    
    def update_phish_headers(self, email):
        # Create the parent div tag.
        div = self.new_tag("div")
        div["style"] = "border:1px solid gray;padding:5px;"
        
        # Make the section header.
        header = self.new_tag("h2", parent=div)
        header.string = "Phish Headers"
        
        # Continue the section if we were given an email.
        if isinstance(email, EmailParser.EmailParser):
            pre = self.new_tag("pre", parent=div)
            pre.string = email.headers

        self.update_section(div, old_section_id="phish_headers")
        
    
    def update_phish_body(self, email):
        # Create the parent div tag.
        div = self.new_tag("div")
        div["style"] = "border:1px solid gray;padding:5px;"
        
        # Make the section header.
        header = self.new_tag("h2", parent=div)
        header.string = "Phish Body"
        
        # Continue the section if we were given an email.
        if isinstance(email, EmailParser.EmailParser):
            pre = self.new_tag("pre", parent=div)
            if email.body:
                pre.string = email.body
            elif email.html:
                pre.string = email.html

        self.update_section(div, old_section_id="phish_body")
        
    
    def update_user_analysis(self, alert_list):
        # Create the parent div tag.
        div = self.new_tag("div")
                
        # Continue building the table if we were given alerts.
        if alert_list:
            # Dedup the list of users from the alerts.
            users = []
            for alert in alert_list:
                if isinstance(alert, ACEAlert.ACEAlert):
                    for user in alert.user_analysis:
                        if user not in users:
                            users.append(user)

            # Only continue if we actually have some users.
            if users:
                # Add the header tag.
                header = self.new_tag("h2", parent=div)
                header.string = "User Analysis"
                
                # Create a new table element.
                table = self.new_tag("table", parent=div)

                # Set up the table header row.
                titles = ["User ID", "Name", "E-mail", "Title", "Description", "Company", "OU"]
                thead = self.new_tag("thead", parent=table)
                tr = self.new_tag("tr", parent=thead)
                for title in titles:
                    th = self.new_tag("th", parent=tr)
                    th.string = title

                # Set up the table body rows.
                tbody = self.new_tag("tbody", parent=table)
                for user in users:
                    tr = self.new_tag("tr", parent=tbody)

                    td = self.new_tag("td", parent=tr)
                    td.string = user["cn"].lower()
                    
                    td = self.new_tag("td", parent=tr)
                    td.string = user["displayName"]
                    
                    td = self.new_tag("td", parent=tr)
                    td.string = user["mail"]
                    
                    td = self.new_tag("td", parent=tr)
                    td.string = user["title"]
                    
                    td = self.new_tag("td", parent=tr)
                    td.string = user["description"][0]
                    
                    td = self.new_tag("td", parent=tr)
                    td.string = user["company"]
                    
                    td = self.new_tag("td", parent=tr)
                    td.string = user["distinguishedName"]
        
        self.update_section(div, old_section_id="user_analysis")
        
    
    def update_url_analysis(self, url_list):
        # Create the parent div tag.
        div = self.new_tag("div")
        div["style"] = "border:1px solid gray;padding:5px;"
        
        # Make the section header.
        header = self.new_tag("h2", parent=div)
        header.string = "URL Analysis"
        
        # Make the pre tag to hold the URLs.
        pre = self.new_tag("pre", parent=div)
        pre.string = ""
        
        # Continue the section if we were given an email.
        for url in url_list:
            pre.string += url + "\n"

        self.update_section(div, old_section_id="url_analysis")
    
    def update_sandbox_analysis(self, sandbox_dict):
        # Get a working copy of the sandbox analysis section.
        #sandbox_analysis = self.get_section("sandbox_analysis")
        
        # Create the parent div tag.
        div = self.new_tag("div")
                
        # Continue if we were given a sandbox dictionary.
        if sandbox_dict:
            # Add the header tag.
            header = self.new_tag("h2", parent=div)
            header.string = "Sandbox Analysis"
            
            for hash in sandbox_dict:
                # Get a single deduped version of the reports.
                dedup_report = BaseSandboxParser.dedup_reports(sandbox_dict[hash])
                        
                # Add a header for the sample's filename.
                header = self.new_tag("h3", parent=div)
                header.string = dedup_report.filename

                ####################
                ##                ##
                ##  SANDBOX URLS  ##
                ##                ##
                ####################
                # Make the new sub-section.
                sandbox_urls_section_id = "sandbox_urls_" + hash
                sandbox_urls_section = self.make_section(sandbox_urls_section_id, parent=div)

                # Create a new parent div for the sub-section.
                sandbox_urls_div = self.new_tag("div")

                # Add a header tag for the URLs.
                header = self.new_tag("h4", parent=sandbox_urls_div)
                header.string = "Sandbox URLs"

                # Add an unordered list for the reports.
                ul = self.new_tag("ul", parent=sandbox_urls_div)

                # Add list items for each report.
                for report in sandbox_dict[hash]:
                    li = self.new_tag("li", parent=ul)
                    li.string = report.sandbox_display_name + " = "
                    link = self.new_tag("a", parent=li)
                    link["href"] = report.sandbox_url
                    link.string = report.filename

                if sandbox_dict[hash][0].sha256:
                    li = self.new_tag("li", parent=ul)
                    link = self.new_tag("a", parent=li)
                    link["href"] = "https://virustotal.com/en/file/" + sandbox_dict[hash][0].sha256 + "/analysis/"
                    link.string = "VirusTotal"

                # Update the sub-section.
                self.update_section(sandbox_urls_div, old_section_soup=sandbox_urls_section)
                
                ###################
                ##               ##
                ##  SCREENSHOTS  ##
                ##               ##
                ###################
                # Only continue if there are actually some screenshots.
                if any(report.screenshot_url for report in sandbox_dict[hash]):
                    # Make the new sub-section.
                    screenshot_section_id = "screenshot_" + hash
                    screenshot_section = self.make_section(screenshot_section_id, parent=div)

                    # Create a new parent div for the sub-section.
                    screenshots_div = self.new_tag("div")

                    # Add a header tag for the screenshots.
                    header = self.new_tag("h4", parent=screenshots_div)
                    header.string = "Screenshots"

                    for report in sandbox_dict[hash]:
                        if report.screenshot_url:
                            screenshot_name = "screenshot_" + report.md5 + "_" + report.sandbox_display_name

                            try:
                                # Download the screenshot image.
                                request = requests.get(report.screenshot_url, verify=self.requests_verify)

                                # If the request was successful, write it to a temp directory.
                                if request.status_code == 200:
                                    with tempfile.TemporaryDirectory() as temp_dir:
                                        screenshot_path = os.path.join(temp_dir, screenshot_name)

                                        with open(screenshot_path, "wb") as screenshot:
                                            screenshot.write(request.content)

                                        # Double check the mimetype of the screenshot to set the correct file extension.
                                        mimetype = magic.from_file(screenshot_path, mime=True)
                                        extension = ""
                                        if "png" in mimetype:
                                            extension = ".png"
                                        if "jpeg" in mimetype:
                                            extension = ".jpg"

                                        # Only attempt to upload the screenshot if we have a valid extension.
                                        if extension:
                                            screenshot_name += extension
                                            os.rename(screenshot_path, screenshot_path + extension)
                                            screenshot_path = screenshot_path + extension

                                            # Upload the screenshot as an attachment if it doesn't already exist.
                                            if not self.attachment_exists(os.path.basename(screenshot_path)):
                                                self.attach_file(screenshot_path)
                            except requests.exceptions.ConnectionError:
                                pass

                            # If the screenshot attachment exists, add an img tag for it.
                            if self.attachment_exists(screenshot_name):
                                title_p = self.new_tag("p", parent=screenshots_div)
                                title_p["style"] = "color:#009000; font-weight:bold;"
                                title_p.string = report.sandbox_display_name + " - " + report.sandbox_vm_name

                                img_p = self.new_tag("p", parent=screenshots_div)
                                img = self.new_tag("img", parent=img_p)
                                img["width"] = "1000"
                                img["height"] = "562"
                                src = "/download/attachments/" + str(self.get_page_id()) + "/" + screenshot_name + "?effects=border-simple,blur-border,tape"
                                img["src"] = src

                    self.update_section(screenshots_div, old_section_soup=screenshot_section)
                
                ###############
                ##           ##
                ##  MUTEXES  ##
                ##           ##
                ###############
                # Only continue if there are actually some mutexes.
                if dedup_report.mutexes:
                    # Make the new sub-section.
                    mutexes_section_id = "mutexes_" + hash
                    mutex_section = self.make_section(mutexes_section_id, parent=div)

                    # Create a new parent div for the sub-section.
                    mutexes_div = self.new_tag("div")
                    mutexes_div["style"] = "border:1px solid gray;padding:5px;"

                    # Add a header tag for the mutexes.
                    header = self.new_tag("h4", parent=mutexes_div)
                    header.string = "Mutexes"
                    
                    # Add a pre tag to hold them.
                    pre = self.new_tag("pre", parent=mutexes_div)
                    pre.string = ""
                    
                    for mutex in dedup_report.mutexes:
                        pre.string += mutex + "\n"

                    self.update_section(mutexes_div, old_section_soup=mutex_section)
                    
                
                #####################
                ##                 ##
                ##  DROPPED FILES  ##
                ##                 ##
                #####################
                # Only continue if there are actually any dropped files.
                if dedup_report.dropped_files:
                    # Make the new sub-section.
                    dropped_section_id = "dropped_" + hash
                    dropped_section = self.make_section(dropped_section_id, parent=div)

                    # Create a new parent div for the sub-section.
                    dropped_div = self.new_tag("div")

                    # Add a header tag for the dropped files.
                    header = self.new_tag("h4", parent=dropped_div)
                    header.string = "Dropped Files"
                    
                    # Create a new table tag.
                    table = self.new_tag("table", parent=dropped_div)

                    # Set up the table header row.
                    thead = self.new_tag("thead", parent=table)
                    tr = self.new_tag("tr", parent=thead)
                    titles = ["VirusTotal", "Filename", "Path", "Size", "Type", "MD5", "SHA256"]
                    for title in titles:
                        th = self.new_tag("th", parent=tr)
                        th.string = title

                    # Set up the table body rows.
                    tbody = self.new_tag("tbody", parent=table)
                    for file in dedup_report.dropped_files:
                        tr = self.new_tag("tr", parent=tbody)

                        td = self.new_tag("td", parent=tr)
                        if file.sha256:
                            url = self.new_tag("a", parent=td)
                            vt_url = "https://virustotal.com/en/file/" + file.sha256 + "/analysis/"
                            url["href"] = vt_url
                            url.string = "VT"

                        td = self.new_tag("td", parent=tr)
                        td.string = file.filename

                        td = self.new_tag("td", parent=tr)
                        td.string = file.path

                        td = self.new_tag("td", parent=tr)
                        td.string = file.size

                        td = self.new_tag("td", parent=tr)
                        td.string = file.type
                        
                        td = self.new_tag("td", parent=tr)
                        td.string = file.md5
                        
                        td = self.new_tag("td", parent=tr)
                        td.string = file.sha256
                        
                    # Update the sub-section.
                    self.update_section(dropped_div, old_section_soup=dropped_section)
                    
                
                ####################
                ##                ##
                ##  DNS REQUESTS  ##
                ##                ##
                ####################
                # Only continue if there are actually any dropped files.
                if dedup_report.dns_requests:
                    # Make the new sub-section.
                    dns_section_id = "dns_" + hash
                    dns_section = self.make_section(dns_section_id, parent=div)

                    # Create a new parent div for the sub-section.
                    dns_div = self.new_tag("div")

                    # Add a header tag for the DNS requests.
                    header = self.new_tag("h4", parent=dns_div)
                    header.string = "DNS Requests"
                    
                    # Create a new table tag.
                    table = self.new_tag("table", parent=dns_div)

                    # Set up the table header row.
                    thead = self.new_tag("thead", parent=table)
                    tr = self.new_tag("tr", parent=thead)
                    titles = ["VirusTotal", "Request", "Type", "VirusTotal", "Answer", "Answer Type"]
                    for title in titles:
                        th = self.new_tag("th", parent=tr)
                        th.string = title

                    # Set up the table body rows.
                    tbody = self.new_tag("tbody", parent=table)
                    for request in dedup_report.dns_requests:
                        tr = self.new_tag("tr", parent=tbody)

                        td = self.new_tag("td", parent=tr)
                        url = self.new_tag("a", parent=td)
                        vt_url = "https://virustotal.com/en/domain/" + request.request + "/information/"
                        url["href"] = vt_url
                        url.string = "VT"

                        td = self.new_tag("td", parent=tr)
                        td.string = request.request

                        td = self.new_tag("td", parent=tr)
                        td.string = request.type

                        td = self.new_tag("td", parent=tr)
                        if request.answer:
                            if RegexHelpers.is_ip(request.answer):
                                vt_url = "https://virustotal.com/en/ip-address/" + request.answer + "/information/"
                            else:
                                vt_url = "https://virustotal.com/en/domain/" + request.answer + "/information/"
                                
                            url = self.new_tag("a", parent=td)
                            url["href"] = vt_url
                            url.string = "VT"

                        td = self.new_tag("td", parent=tr)
                        td.string = request.answer
                        
                        td = self.new_tag("td", parent=tr)
                        td.string = request.answer_type
                        
                    # Update the sub-section.
                    self.update_section(dns_div, old_section_soup=dns_section)
                
                #####################
                ##                 ##
                ##  HTTP REQUESTS  ##
                ##                 ##
                #####################
                # Only continue if there are actually any dropped files.
                if dedup_report.http_requests:
                    # Make the new sub-section.
                    http_section_id = "http_" + hash
                    http_section = self.make_section(http_section_id, parent=div)

                    # Create a new parent div for the sub-section.
                    http_div = self.new_tag("div")

                    # Add a header tag for the DNS requests.
                    header = self.new_tag("h4", parent=http_div)
                    header.string = "HTTP Requests"
                    
                    # Create a new table tag.
                    table = self.new_tag("table", parent=http_div)

                    # Set up the table header row.
                    thead = self.new_tag("thead", parent=table)
                    tr = self.new_tag("tr", parent=thead)
                    titles = ["VirusTotal", "Method", "Host", "URI", "Port", "User-Agent"]
                    for title in titles:
                        th = self.new_tag("th", parent=tr)
                        th.string = title

                    # Set up the table body rows.
                    tbody = self.new_tag("tbody", parent=table)
                    for request in dedup_report.http_requests:
                        tr = self.new_tag("tr", parent=tbody)

                        td = self.new_tag("td", parent=tr)
                        url = self.new_tag("a", parent=td)
                        full_url = "http://" + request.host + request.uri
                        url_hash = hashlib.sha256(full_url.encode()).hexdigest()
                        vt_url = "https://virustotal.com/en/url/" + url_hash + "/analysis/"
                        url["href"] = vt_url
                        url.string = "VT"

                        td = self.new_tag("td", parent=tr)
                        td.string = request.method

                        td = self.new_tag("td", parent=tr)
                        td.string = request.host

                        td = self.new_tag("td", parent=tr)
                        td.string = request.uri
                        
                        td = self.new_tag("td", parent=tr)
                        td.string = request.port

                        td = self.new_tag("td", parent=tr)
                        td.string = request.user_agent
                        
                    # Update the sub-section.
                    self.update_section(http_div, old_section_soup=http_section)
                    
                
                #######################
                ##                   ##
                ##  CONTACTED HOSTS  ##
                ##                   ##
                #######################
                # Only continue if there are actually any dropped files.
                if dedup_report.contacted_hosts:
                    # Make the new sub-section.
                    hosts_section_id = "hosts_" + hash
                    hosts_section = self.make_section(hosts_section_id, parent=div)

                    # Create a new parent div for the sub-section.
                    hosts_div = self.new_tag("div")

                    # Add a header tag for the DNS requests.
                    header = self.new_tag("h4", parent=hosts_div)
                    header.string = "Contacted Hosts"
                    
                    # Create a new table tag.
                    table = self.new_tag("table", parent=hosts_div)

                    # Set up the table header row.
                    thead = self.new_tag("thead", parent=table)
                    tr = self.new_tag("tr", parent=thead)
                    titles = ["VirusTotal", "Address", "Port", "Protocol", "Location", "Associated Domains"]
                    for title in titles:
                        th = self.new_tag("th", parent=tr)
                        th.string = title

                    # Set up the table body rows.
                    tbody = self.new_tag("tbody", parent=table)
                    for host in dedup_report.contacted_hosts:
                        tr = self.new_tag("tr", parent=tbody)

                        td = self.new_tag("td", parent=tr)
                        url = self.new_tag("a", parent=td)
                        vt_url = "https://virustotal.com/en/ip-address/" + host.ipv4 + "/information/"
                        url["href"] = vt_url
                        url.string = "VT"

                        td = self.new_tag("td", parent=tr)
                        td.string = host.ipv4

                        td = self.new_tag("td", parent=tr)
                        td.string = host.port

                        td = self.new_tag("td", parent=tr)
                        td.string = host.protocol

                        td = self.new_tag("td", parent=tr)
                        td.string = host.location
                        
                        td = self.new_tag("td", parent=tr)
                        td.string = host.associated_domains_string
                        
                    # Update the sub-section.
                    self.update_section(hosts_div, old_section_soup=hosts_section)
                    
                    
                
                #####################
                ##                 ##
                ##  PROCESS TREES  ##
                ##                 ##
                #####################
                # Only continue if there are actually some process trees.
                if dedup_report.process_tree_list:
                    # Make the new sub-section.
                    process_section_id = "process_" + hash
                    process_section = self.make_section(process_section_id, parent=div)

                    # Create a new parent div for the sub-section.
                    process_div = self.new_tag("div")
                    process_div["style"] = "border:1px solid gray;padding:5px;"

                    # Add a header tag for the mutexes.
                    header = self.new_tag("h4", parent=process_div)
                    header.string = "Process Tree"
                    
                    # Add a pre tag to hold them.
                    pre = self.new_tag("pre", parent=process_div)
                    pre.string = ""
                    
                    for tree in dedup_report.process_tree_list:
                        pre.string += tree + "\n"

                    self.update_section(process_div, old_section_soup=process_section)
                
        self.update_section(div, old_section_id="sandbox_analysis")