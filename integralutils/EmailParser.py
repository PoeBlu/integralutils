import os
import email
import re
from email.header import decode_header, make_header
import binascii
import base64
import sys
from email.parser import Parser as EmailParser
from email.utils import parseaddr
import hashlib
import dateutil.parser
from dateutil import tz
from urllib.parse import urlsplit
from urllib.parse import *

from integralutils import RegexHelpers

class EmailParser():
    def __init__(self, smtp_path):
        # Read the SMTP file. This works with the "smtp.stream" file or in theory
        # an "smtp.email" type file with the SMTP commands removed.
        if os.path.exists(smtp_path):
            self.path = smtp_path
            self.name = os.path.basename(smtp_path)

        with open(self.path) as s:
            smtp_stream = s.readlines()
            
        # Find the envelope from/to addresses. This will only work if given an
        # "smtp.stream" file, since otherwise the SMTP commands will not exist.
        # This should in theory change to a custom header field when we move
        # to Office 365.
        self.envelope_from = ""
        self.envelope_to = ""
        envelope_address_pattern = re.compile(r'.*<(.*)>.*')
        for line in smtp_stream:
            if line.startswith("MAIL FROM:"):
                try:
                    self.envelope_from = envelope_address_pattern.match(line).group(1)
                except AttributeError:
                    self.envelope_from = ""
            if line.startswith("RCPT TO:"):
                try:
                    self.envelope_to = envelope_address_pattern.match(line).group(1)
                except AttributeError:
                    self.envelope_to = ""

        # Just in case we are dealing with an "smtp.stream" file that still has
        # the SMTP commands above the actual e-mail, we need to strip those out.
        # This will remove all lines prior to the Received: headers so that the
        # email.parser can properly parse out the e-mail. If we were given an
        # "smtp.email" type of file with the SMTP commands already removed, this
        # should not affect anything.
        while not smtp_stream[0].startswith("Received:"):
            smtp_stream.pop(0)

        # Parse out the email object.
        email_text = "".join(smtp_stream)
        self.__email_obj = email.message_from_string(email_text)
        
        # Parse the e-mail object for its content.
        parsed_email = self.__parse_content()
        
        # Now that we have the e-mail object, parse out the parts.
        self.urls = set()
        self.headers = self.__get_all_headers_string()
        self.received = self.__get_header("received")
        self.subject = "".join(str(make_header(decode_header(self.__get_header("subject")[0]))).splitlines())
        self.body = parsed_email["body"]
        self.html = parsed_email["html"]
        self.attachments = parsed_email["attachments"]
        self.from_address = self.__get_address_list("from")[0][1]
        self.to_list = [x[1] for x in self.__get_address_list("to")]
        self.cc_list = [x[1] for x in self.__get_address_list("cc")]
        self.bcc_list = [x[1] for x in self.__get_address_list("bcc")]
        self.message_id = self.__get_header("message-id")[0]
                
        try: self.x_mailer = self.__get_header("x-mailer")[0]
        except IndexError: self.x_mailer = ""
        
        try: self.x_original_sender = self.__get_header("x-original-sender")[0]
        except IndexError: self.x_original_sender = ""
        
        try:
            x_originating_ip = self.__get_header("x-originating-ip")[0]
            # Sometimes this field is in the form: [1.1.1.1]
            # So make sure we remove any non-IP characters.
            ip = RegexHelpers.find_ip_addresses(x_originating_ip)
            if ip:
                self.x_originating_ip = ip[0]
        except IndexError:
            self.x_originating_ip = ""
        
        try:
            x_sender_ip = self.__get_header("x-sender-ip")[0]
            # Just make sure like the X-Originating-IP that we only
            # get the IP address and no other characters.
            ip_pattern = "(\d+\.\d+\.\d+\.\d+)"
            ip_match = re.search(ip_pattern, x_sender_ip)
            
            if ip_match:
                self.x_sender_ip = ip_match.group(1)
        except IndexError:
            self.x_sender_ip = ""
        
        text_urls = RegexHelpers.find_urls(self.body)
        html_urls = RegexHelpers.find_urls(self.html)
        all_urls = text_urls + html_urls
        for file in self.attachments:
            if "strings_urls" in file:
                all_urls += file["strings_urls"]

        # Parse the URLs so that we can create Indicators and also prevent
        # "duplicate" URLs like http://blah.com/ and http://blah.com
        for url in all_urls:
            # Strip off the ending slash if it's there.
            if url.endswith("/"):
                self.urls.add(url[:-1])
            else:
                self.urls.add(url)
                        
        self.received_time = self.__get_received_time()
        
        try:
            self.replyto = self.__get_address_list("reply-to")[0][1]
        except IndexError:
            self.replyto = ""
        
    def __get_header(self, header_name):
        return self.__email_obj.get_all(header_name, [])

    def __get_all_headers_string(self):
        header_string = ""

        for header in self.__email_obj.items():
            header_string += ": ".join(header) + "\n"

        return header_string

    def __get_address_list(self, header_name):
        header = self.__email_obj.get_all(header_name, [])
        return email.utils.getaddresses(header)

    def __get_received_time(self):
        header=self.__email_obj.get_all("received", [])
        last_received_lines = header[0]
        
        received_time_pattern = re.compile(r"[A-Z][a-z]{2,3},\s+\d+\s+[A-Z][a-z]{2,3}\s+[0-9]{4}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\s*(\+\d+|\-\d+)*")
        last_received_time = re.search(received_time_pattern, last_received_lines)
        
        if last_received_time:
            datetime_obj = dateutil.parser.parse(last_received_time.group(0), ignoretz=False)
            datetime_string = str(datetime_obj)
            EST = tz.gettz('America/Detroit')
            localtime_string = str(datetime_obj.astimezone(EST))
            return localtime_string
        else:
            return ""

    def __get_received_for_address(self):
        received_header = self.__email_obj.get_all('received', [])
        receivedfor_info = email.utils.getaddresses(received_header)
        for tup in receivedfor_info:
            if "for" in tup[0] and "@" in tup[1]:
                return tup[1]
        return None

    def __get_charset(self, obj, default="ascii"):
        if obj.get_content_charset():
            return obj.get_content_charset()
            
        if obj.get_charset():
            return obj.get_charset()
            
        return default

    # Adapted from: https://www.ianlewis.org/en/parsing-email-attachments-python
    def __parse_content(self):
        attachments = []
        body = ""
        html = ""
        for part in self.__email_obj.walk():
            charset = self.__get_charset(part, self.__get_charset(self.__email_obj))
            attachment = self.__parse_attachment(part, charset)
            if attachment:
                attachments.append(attachment)
            elif part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(charset)
            elif part.get_content_type() == "text/html":
                html += part.get_payload(decode=True).decode(charset)
        return {
            'body' : body,
            'html' : html,
            'attachments': attachments
        }

    # Adapted from: https://www.ianlewis.org/en/parsing-email-attachments-python
    def __parse_attachment(self, message_part, charset):
        content_disposition = message_part.get("Content-Disposition", None)
        if content_disposition:
            dispositions = content_disposition.strip().split(";")
            if bool(content_disposition and dispositions[0].lower() == "attachment"):
                file_data = message_part.get_payload()
                
                attachment_dict = {}
                if message_part.get("Content-Transfer-Encoding", None) == "base64":
                    file_data_b64 = file_data.replace("\n", "")
                    # For some reason, sometimes the attachments don't have the proper
                    # padding. Add a couple "==" on the end for good measure.
                    file_data_decoded = base64.b64decode(file_data_b64 + "==")
                    
                    # Try and get strings out of the attachment.
                    strings_list = RegexHelpers.find_strings(file_data_decoded)
                    strings = " ".join(strings_list)
                    
                    # Look for any URLs that were in the strings.
                    strings_urls = RegexHelpers.find_urls(strings)
                    attachment_dict["strings_urls"] = strings_urls
                    
                elif message_part.get_content_type() == "text/html":
                    file_data_decoded = message_part.get_payload(decode=True).decode(charset).encode('utf-8')
                else:
                    file_data_decoded = file_data
                    
                md5_hasher = hashlib.md5()
                md5_hasher.update(file_data_decoded)
                md5_hash = md5_hasher.hexdigest()
                
                sha256_hasher = hashlib.sha256()
                sha256_hasher.update(file_data_decoded)
                sha256_hash = sha256_hasher.hexdigest()

                attachment_dict["data"] = file_data_decoded
                attachment_dict["content_type"] = message_part.get_content_type()
                attachment_dict["size"] = len(file_data_decoded)
                attachment_dict["md5"] = md5_hash
                attachment_dict["sha256"] = sha256_hash
                attachment_dict["name"] = None
                attachment_dict["create_date"] = None
                attachment_dict["mod_date"] = None
                attachment_dict["read_date"] = None
                
                for param in dispositions[1:]:
                    # Only split 1 time in case the filename has an "=" in it.
                    name,value = param.split("=", 1)
                    name = name.lower().strip()

                    if name == "filename":
                        attachment_dict["name"] = "".join(value.splitlines()).replace("\"", "")
                        value = value.replace("\"", "")
                        attachment_dict["name"] = RegexHelpers.decode_utf_b64_string(value)

                    elif name == "create-date":
                        attachment_dict["create_date"] = value  #TODO: datetime
                    elif name == "modification-date":
                        attachment_dict["mod_date"] = value #TODO: datetime
                    elif name == "read-date":
                        attachment_dict["read_date"] = value #TODO: datetime

                return attachment_dict

        return None
    
    def write_attachments(self, output_path):
        if os.path.exists(output_path):
            for attachment in self.attachments:
                if attachment["name"]:
                    attachment_path = os.path.join(output_path, attachment["name"])

                    with open(attachment_path, 'wb') as output:
                        output.write(attachment["data"])
