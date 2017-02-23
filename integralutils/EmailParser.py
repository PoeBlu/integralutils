import os
import email
import re
from email.header import decode_header, make_header
import base64
import hashlib
import dateutil.parser
from dateutil import tz
from dateutil.tz import tzlocal
import datetime
from bs4 import BeautifulSoup

from integralutils import RegexHelpers

class EmailParser():
    def __init__(self, smtp_path=None, smtp_text=None, attached_email=True):
        # Check that we got at least an SMTP path or text:
        if not smtp_path and not smtp_text:
            raise ValueError("You must specify either an SMTP path or the SMTP text.")
            
        # In case we received both, default to use the smtp_path over the smtp_text.
        if smtp_path:
            # Read the SMTP file. This works with the "smtp.stream" file or in theory
            # an "smtp.email" type file with the SMTP commands removed.
            if os.path.exists(smtp_path):
                self.path = smtp_path
                self.name = os.path.basename(smtp_path)

            with open(self.path) as s:
                smtp_stream = s.read().splitlines()
        else:
            smtp_stream = smtp_text.splitlines()
                        
        # Find the envelope from/to addresses. This will only work if given an
        # "smtp.stream" file, since otherwise the SMTP commands will not exist.
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
                    
        # Exchange journaling sends us the e-mail embedded as an attachment within
        # another e-mail. We need to strip away those outer headers so that we parse
        # the attached e-mail that we actually care about.
        if attached_email:
            if "Content-Type: message/rfc822" in smtp_stream:
                index = smtp_stream.index("Content-Type: message/rfc822")
                smtp_stream = smtp_stream[index:]

        # Just in case we are dealing with an "smtp.stream" file that still has
        # the SMTP commands above the actual e-mail, we need to strip those out.
        # This will remove all lines prior to the Received: headers so that the
        # email.parser can properly parse out the e-mail. If we were given an
        # "smtp.email" type of file with the SMTP commands already removed, this
        # should not affect anything.
        while not smtp_stream[0].startswith("Received:"):
            smtp_stream.pop(0)

        # Parse out the email object.
        email_text = "\n".join(smtp_stream)
        self._email_obj = email.message_from_string(email_text)
        
        # Parse the e-mail object for its content.
        parsed_email = self._parse_content()
        
        # Now that we have the e-mail object, parse out some of the interesting parts.
        self.urls = set()
        self.headers = self._get_all_headers_string()
        self.received = self.get_header("received")
        
        try: self.subject = "".join(self.get_header("subject")[0].splitlines())
        except IndexError: self.subject = ""
            
        try: self.decoded_subject = "".join(str(make_header(decode_header(self.get_header("subject")[0]))).splitlines())
        except IndexError: self.decoded_subject = ""
            
        self.body = parsed_email["body"]
        self.html = parsed_email["html"]
        if self.html:
            soup = BeautifulSoup(self.html, "html.parser")
            self.visible_html = "".join(soup.findAll(text=True))
            
        self.attachments = parsed_email["attachments"]
        
        try: self.from_address = self._get_address_list("from")[0][1]
        except IndexError: self.from_address = ""

        self.to_list = [x[1] for x in self._get_address_list("to")]
        self.cc_list = [x[1] for x in self._get_address_list("cc")]
        self.bcc_list = [x[1] for x in self._get_address_list("bcc")]

        try: self.message_id = self.get_header("message-id")[0]
        except IndexError: self.message_id = ""
                
        try: self.x_mailer = self.get_header("x-mailer")[0]
        except IndexError: self.x_mailer = ""
        
        try: self.x_original_sender = self.get_header("x-original-sender")[0]
        except IndexError: self.x_original_sender = ""
        
        try:
            x_originating_ip = self.get_header("x-originating-ip")[0]
            # Sometimes this field is in the form: [1.1.1.1]
            # Make sure we remove any non-IP characters.
            ip = RegexHelpers.find_ip_addresses(x_originating_ip)
            if ip:
                self.x_originating_ip = ip[0]
        except IndexError:
            self.x_originating_ip = ""
        
        try:
            x_sender_ip = self.get_header("x-sender-ip")[0]
            # Make sure like the X-Originating-IP that we only
            # get the IP address and no other characters.
            ip = RegexHelpers.find_ip_addresses(x_sender_ip)
            
            if ip:
                self.x_sender_ip = ip[0]
        except IndexError:
            self.x_sender_ip = ""
        
        text_urls = RegexHelpers.find_urls(self.body)
        html_urls = RegexHelpers.find_urls(self.html)
        all_urls = text_urls + html_urls
        for file in self.attachments:
            if "strings_urls" in file:
                all_urls += file["strings_urls"]

        # Parse the URLs and prevent "duplicate" URLs
        # like http://blah.com/ and http://blah.com
        for url in all_urls:
            # Strip off the ending slash if it's there.
            if url.endswith("/"):
                self.urls.add(url[:-1])
            else:
                self.urls.add(url)
                        
        self.received_time = self._get_received_time()
        
        try: self.replyto = self._get_address_list("reply-to")[0][1]
        except IndexError: self.replyto = ""
        
    def get_header(self, header_name):
        return self._email_obj.get_all(header_name, [])

    def _get_all_headers_string(self):
        header_string = ""

        for header in self._email_obj.items():
            header_string += ": ".join(header) + "\n"

        return header_string

    def _get_address_list(self, header_name):
        header = self._email_obj.get_all(header_name, [])
        return email.utils.getaddresses(header)

    def _get_received_time(self):
        header=self._email_obj.get_all("received", [])
        last_received_lines = header[0]
        
        received_time_pattern = re.compile(r"[A-Z][a-z]{2,3},\s+\d+\s+[A-Z][a-z]{2,3}\s+[0-9]{4}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\s*(\+\d+|\-\d+)*")
        last_received_time = re.search(received_time_pattern, last_received_lines)
        
        if last_received_time:
            datetime_obj = dateutil.parser.parse(last_received_time.group(0), ignoretz=False)
            localtime = dateutil.tz.tzlocal()
            localtime_string = str(datetime_obj.astimezone(localtime))
            return localtime_string
        else:
            return ""

    def _get_received_for_address(self):
        received_header = self._email_obj.get_all('received', [])
        receivedfor_info = email.utils.getaddresses(received_header)
        for tup in receivedfor_info:
            if "for" in tup[0] and "@" in tup[1]:
                return tup[1]
        return None

    def _get_charset(self, obj, default="ascii"):
        if obj.get_content_charset():
            return obj.get_content_charset()
            
        if obj.get_charset():
            return obj.get_charset()
            
        return default

    # Adapted from: https://www.ianlewis.org/en/parsing-email-attachments-python
    def _parse_content(self):
        attachments = []
        body = ""
        html = ""
        for part in self._email_obj.walk():
            charset = self._get_charset(part, self._get_charset(self._email_obj))
            attachment = self._parse_attachment(part, charset)
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
    def _parse_attachment(self, message_part, charset):
        part_items = message_part.items()
        for tup in part_items:
            for value in tup:
                if "attachment" in value:
                    file_data = message_part.get_payload()

                    attachment_dict = {}
                    if message_part.get("Content-Transfer-Encoding", None) == "base64":
                        file_data_b64 = file_data.replace("\n", "")
                        # For some reason, sometimes the attachments don't have the proper
                        # padding. Add a couple "==" on the end for good measure. This doesn't
                        # seem to harm correctly encoded attachments.
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
                    attachment_dict["name"] = ""
                    attachment_dict["create_date"] = None
                    attachment_dict["mod_date"] = None
                    attachment_dict["read_date"] = None

                    # Find the attachment name. Normally this follows a specific format
                    # and is called 'filename=' but recently I've seen some that are in
                    # different locations are are just called 'name='... Hence removing
                    # old code and replacing with a regex statement to account for either
                    # name in any location in the message part.
                    attachment_name_pattern = re.compile(r'(file)?name="(.*?)"')
                    for tup in part_items:
                        for item in tup:
                            attachment_name = attachment_name_pattern.search(item)
                            if attachment_name:
                                attachment_dict["name"] = RegexHelpers.decode_utf_b64_string(attachment_name.groups()[1])

                    return attachment_dict

        return None
    
    def write_attachments(self, output_path):
        if os.path.exists(output_path):
            for attachment in self.attachments:
                if attachment["name"]:
                    attachment_path = os.path.join(output_path, attachment["name"])
                else:
                    attachment_path = os.path.join(output_path, attachment["md5"])

                with open(attachment_path, 'wb') as output:
                    output.write(attachment["data"])
