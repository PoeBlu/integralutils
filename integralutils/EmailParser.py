import os
import email
import logging
import re
from email.header import decode_header, make_header
import base64
import hashlib
import dateutil.parser
from dateutil import tz
from dateutil.tz import tzlocal
import datetime
from bs4 import BeautifulSoup
import sys

# Make sure the current directory is in the
# path so that we can run this from anywhere.
this_dir = os.path.dirname(__file__)
if this_dir not in sys.path:
    sys.path.insert(0, this_dir)

import RegexHelpers
import Indicator
import Whitelist

class EmailParser():
    def __init__(self, config, smtp_path=None, smtp_text=None, attached_email=True, whitelister=None, check_whitelist=False):
        # Initiate logging.
        self.logger = logging.getLogger()

        # Save the config. This should be a ConfigParser object.
        self.config = config

        # Save the whitelister. This should be a Whitelist object.
        self.whitelister = whitelister
        self.check_whitelist = check_whitelist

        # Check that we got at least an SMTP path or text:
        if not smtp_path and not smtp_text:
            self.logger.critical("You must specify either an SMTP path or the SMTP text.")
            return None
            
        # In case we received both, default to use the smtp_path over the smtp_text.
        if smtp_path:
            # Read the SMTP file. This works with the "smtp.stream" file or in theory
            # an "smtp.email" type file with the SMTP commands removed.
            if os.path.exists(smtp_path):
                self.path = smtp_path
                self.name = os.path.basename(smtp_path)

            self.logger.info("Parsing e-mail: " + self.path)
            with open(self.path) as s:
                smtp_stream = s.read().splitlines()
        else:
            smtp_stream = smtp_text.splitlines()
            # path and name are here just for completeness for anything
            # external that might rely on them.
            self.path = ""
            self.name = hashlib.md5(smtp_text.encode('utf-8')).hexdigest()
                        
        # A place to store the IOCs.
        self.iocs = []
        
        # Where did this alert come from? This could be anything, such as
        # a URL to an ACE alert or whatever other reference you want.
        self.reference = ""
        
        # Find the envelope from/to addresses. This will only work if given an
        # "smtp.stream" file, since otherwise the SMTP commands will not exist.
        self.envelope_from = ""
        self.envelope_to = ""
        envelope_address_pattern = re.compile(r'.*<(.*)>.*')
        for line in smtp_stream:
            if line.startswith("MAIL FROM:"):
                try:
                    # Make an Indicator for the address.
                    self.envelope_from = envelope_address_pattern.match(line).group(1)
                    try:
                        ind = Indicator.Indicator(self.envelope_from, "Email - Address")
                        ind.add_tags(["phish", "envelope_from_address"])
                        self.iocs.append(ind)
                    except ValueError:
                        pass
                except AttributeError:
                    self.envelope_from = ""
            if line.startswith("RCPT TO:"):
                try:
                    # Make an Indicator for the address.
                    self.envelope_to = envelope_address_pattern.match(line).group(1)
                    try:
                        ind = Indicator.Indicator(self.envelope_from, "Email - Address")
                        ind.add_tags(["phish", "envelope_to_address"])
                        self.iocs.append(ind)
                    except ValueError:
                        pass
                except AttributeError:
                    self.envelope_to = ""
                    
        # Exchange journaling sends us the e-mail embedded as an attachment within
        # another e-mail. We need to strip away those outer headers so that we parse
        # the attached e-mail that we actually care about.
        #if attached_email:
        #    if "Content-Type: message/rfc822" in smtp_stream:
        #        index = smtp_stream.index("Content-Type: message/rfc822")
        #        smtp_stream = smtp_stream[index:]

        # Just in case we are dealing with an "smtp.stream" file that still has
        # the SMTP commands above the actual e-mail, we need to strip those out.
        # This will remove all lines prior to the Received: headers so that the
        # email.parser can properly parse out the e-mail. If we were given an
        # "smtp.email" type of file with the SMTP commands already removed, this
        # should not affect anything.
        while not smtp_stream[0].startswith("Received:"):
            smtp_stream.pop(0)

        # Join the header lines into a single string.
        email_text = "\n".join(smtp_stream)
        
        # Create the e-mail object.
        self._email_obj = email.message_from_string(email_text)
        
        # If we want to try and parse an embedded/attached e-mail instead...
        if attached_email:
            # Walk the full e-mail's parts.
            for part in self._email_obj.walk():
                # Continue if the part looks like a valid e-mail.
                if part.get_content_type() == "message/rfc822":
                    # Split the part lines into a list.
                    part_text = str(part).splitlines()
                    if any("Received:" in line for line in part_text):
                        # Make sure our part starts with the Received: headers.
                        while not part_text[0].startswith("Received:"):
                            part_text.pop(0)
                        part_text = "\n".join(part_text)

                        # Make the new e-mail object.
                        self._email_obj = email.message_from_string(part_text)

        # Remove any 'bad' headers that we don't care about.
        bad_headers = self.config.get('EmailParser', 'bad_headers', fallback=None)
        if bad_headers:
            try:
                bad_headers = bad_headers.split(',')

                for header in self._email_obj.keys():
                    if any(bad_header in header for bad_header in bad_headers):
                        self._email_obj.__delitem__(header)
            except:
                self.logger.warning('Unable to delete header: {}'.format(header))

        # Parse the e-mail object for its content.
        parsed_email = self._parse_content()
        
        # Now that we have the e-mail object, parse out some of the interesting parts.
        self.urls = set()
        self.headers = self._get_all_headers_string()
                
        # Make Indicators for the received headers (SMTP relays)
        self.received = self.get_header("received")
        for hop in self.received:
            for ip in RegexHelpers.find_ip_addresses(hop):
                try:
                    ind = Indicator.Indicator(ip, "Address - ipv4-addr")
                    ind.add_tags(["phish", "smtp_relay"])
                    # We consider SMTP relay indicators benign... Don't want to alert every time
                    # we see the relay sending an e-mail, but it's nice to know for correlation.
                    ind.make_benign()
                    self.iocs.append(ind)
                except ValueError:
                    pass

            for domain in RegexHelpers.find_domains(hop):
                if isinstance(domain, tuple):
                    try:
                        ind = Indicator.Indicator(domain[0], "URI - Domain Name")
                        ind.add_tags(["phish", "smtp_relay"])
                        ind.make_benign()
                        self.iocs.append(ind)
                    except ValueError:
                        pass

        # Get the e-mail's plaintext body, HTML body, and the visible text from the HTML.
        self.body = parsed_email["body"]
        self.html = parsed_email["html"]
        if self.html:
            soup = BeautifulSoup(self.html, "html.parser")
            self.visible_html = "".join(soup.findAll(text=True))
        else:
            self.visible_html = ""
        
        # Get any e-mail attachments.
        self.attachments = parsed_email["attachments"]
        self.attachments_string = ", ".join([attach["name"] for attach in self.attachments])
        self.md5_string = ", ".join([attach["md5"] for attach in self.attachments])
        
        # Make an Indicator for the from address.
        try:
            self.from_address = self._get_address_list("from")[0][1]
            try:
                ind = Indicator.Indicator(self.from_address, "Email - Address")
                ind.add_tags(["phish", "from_address"])
                self.iocs.append(ind)
            except ValueError:
                pass
        except IndexError:
            self.from_address = ""
            
        # Make an Indicator for the reply-to address.
        try:
            self.replyto = self._get_address_list("reply-to")[0][1]
            try:
                ind = Indicator.Indicator(self.replyto, "Email - Address")
                ind.add_tags(["phish", "replyto_address"])
                if self.from_address:
                    ind.add_relationships(self.from_address)
                self.iocs.append(ind)
            except ValueError:
                pass
        except IndexError:
            self.replyto = ""

        # Make an Indicator for the X-Sender-Id address.
        try:
            self.x_sender_id = self._get_address_list("X-Sender-Id")[0][1]
            try:
                if RegexHelpers.is_email_address(self.x_sender_id):
                    ind = Indicator.Indicator(self.x_sender_id, "Email - Address")
                    ind.add_tags(["phish", "x_sender_id"])
                    if self.from_address:
                        ind.add_relationships(self.from_address)
                    self.iocs.append(ind)
            except ValueError:
                pass
        except IndexError:
            self.x_sender_id = ""

        # Make an Indicator for the X-Auth-ID address.
        try:
            self.x_auth_id = self._get_address_list("X-Auth-ID")[0][1]
            try:
                if RegexHelpers.is_email_address(self.x_auth_id):
                    ind = Indicator.Indicator(self.x_auth_id, "Email - Address")
                    ind.add_tags(["phish", "x_auth_id"])
                    if self.from_address:
                        ind.add_relationships(self.from_address)
                    self.iocs.append(ind)
            except ValueError:
                pass
        except IndexError:
            self.x_auth_id = ""

        # Make an Indicator for the Return-Path address.
        try:
            self.return_path = self._get_address_list("return_path")[0][1]
            try:
                if RegexHelpers.is_email_address(self.return_path):
                    ind = Indicator.Indicator(self.return_path, "Email - Address")
                    ind.add_tags(["phish", "return_path"])
                    if self.from_address:
                        ind.add_relationships(self.from_address)
                    self.iocs.append(ind)
            except ValueError:
                pass
        except IndexError:
            self.return_path = ""

        # Make an Indicator for the X-MS-Exchange-Organization-OriginalEnvelopeRecipients address.
        try:
            self.env_recipient = self._get_address_list("X-MS-Exchange-Organization-OriginalEnvelopeRecipients")[0][1]
            try:
                if RegexHelpers.is_email_address(self.env_recipient):
                    ind = Indicator.Indicator(self.env_recipient, "Email - Address")
                    ind.add_tags(["phish", "env_recipient"])
                    if self.from_address:
                        ind.add_relationships(self.from_address)
                    ind.make_benign() 
                    self.iocs.append(ind)
            except ValueError:
                pass
        except IndexError:
            self.env_recipient = ""
            
        # Make an Indicator for the subject.
        try:
            self.subject = "".join(self.get_header("subject")[0].splitlines())
            try:
                ind = Indicator.Indicator(self.subject, "Email - Subject")
                ind.add_tags(["phish", "subject"])
                if self.from_address:
                    ind.add_relationships(self.from_address)
                self.iocs.append(ind)
            except ValueError:
                pass
        except IndexError:
            self.subject = ""
            
        # Try and decode the subject and make an Indicator.
        try:
            self.decoded_subject = "".join(str(make_header(decode_header(self.get_header("subject")[0]))).splitlines())
            try:
                ind = Indicator.Indicator(self.decoded_subject, "Email - Subject")
                ind.add_tags(["phish", "decoded_subject"])
                if self.from_address:
                    ind.add_relationships(self.from_address)
                self.iocs.append(ind)
            except ValueError:
                pass
        except IndexError:
            self.decoded_subject = ""

        # Make an Indicator for each to address.
        self.to_list = [x[1] for x in self._get_address_list("to")]
        self.to_string = ", ".join(self.to_list).replace("\t", " ")
        #for address in self.to_list:
        #    try:
        #        ind = Indicator.Indicator(address, "Email - Address")
        #        ind.add_tags(["phish", "to_address"])
        #        if self.from_address:
        #            ind.add_relationships(self.from_address)
        #        self.iocs.append(ind)
        #    except ValueError:
        #        pass
            
        # Make an Indicator for each CC address.
        self.cc_list = [x[1] for x in self._get_address_list("cc")]
        self.cc_string = ", ".join(self.cc_list).replace("\t", " ")
        #for address in self.cc_list:
        #    try:
        #        ind = Indicator.Indicator(address, "Email - Address")
        #        ind.add_tags(["phish", "cc_address"])
        #        if self.from_address:
        #            ind.add_relationships(self.from_address)
        #        self.iocs.append(ind)
        #    except ValueError:
        #        pass
        
        # Make an Indicator for each BCC address.
        self.bcc_list = [x[1] for x in self._get_address_list("bcc")]
        self.bcc_string = ", ".join(self.bcc_list).replace("\t", " ")
        #for address in self.bcc_list:
        #    try:
        #        ind = Indicator.Indicator(address, "Email - Address")
        #        ind.add_tags(["phish", "bcc_address"])
        #        if self.from_address:
        #            ind.add_relationships(self.from_address)
        #        self.iocs.append(ind)
        #    except ValueError:
        #        pass

        # Make an Indicator for the message ID.
        try:
            self.message_id = self.get_header("message-id")[0]
            try:
                ind = Indicator.Indicator(self.message_id, "Email Message ID")
                ind.add_tags(["phish", "message_id"])
                if self.from_address:
                    ind.add_relationships(self.from_address)
                self.iocs.append(ind)
            except ValueError:
                pass
        except IndexError:
            self.message_id = ""
                
        # Make an Indicator for the x-mailer.
        try:
            self.x_mailer = self.get_header("x-mailer")[0]
            try:
                ind = Indicator.Indicator(self.x_mailer, "Email - Xmailer")
                ind.add_tags(["phish", "x-mailer"])
                if self.from_address:
                    ind.add_relationships(self.from_address)
                self.iocs.append(ind)
            except ValueError:
                pass
        except IndexError:
            self.x_mailer = ""
        
        # Make an Indicator for the x-original-sender.
        try:
            self.x_original_sender = self.get_header("x-original-sender")[0]
            try:
                ind = Indicator.Indicator(address, "Email - Address")
                ind.add_tags(["phish", "x-original-sender"])
                if self.from_address:
                    ind.add_relationships(self.from_address)
                self.iocs.append(ind)
            except ValueError:
                pass
        except IndexError:
            self.x_original_sender = ""
        
        # Make an Indicator for the x-originating-ip.
        try:
            x_originating_ip = self.get_header("x-originating-ip")[0]
            # Sometimes this field is in the form: [1.1.1.1]
            # Make sure we remove any non-IP characters.
            ip = RegexHelpers.find_ip_addresses(x_originating_ip)
            if ip:
                self.x_originating_ip = ip[0]
                try:
                    ind = Indicator.Indicator(self.x_originating_ip, "Address - ipv4-addr")
                    ind.add_tags(["phish", "x-originating-ip"])
                    if self.from_address:
                        ind.add_relationships(self.from_address)
                    self.iocs.append(ind)
                except ValueError:
                    pass
        except IndexError:
            self.x_originating_ip = ""
        
        # Make an Indicator for the x-sender-ip.
        try:
            x_sender_ip = self.get_header("x-sender-ip")[0]
            # Make sure like the X-Originating-IP that we only
            # get the IP address and no other characters.
            ip = RegexHelpers.find_ip_addresses(x_sender_ip)
            if ip:
                self.x_sender_ip = ip[0]
                try:
                    ind = Indicator.Indicator(self.x_sender_ip, "Address - ipv4-addr")
                    ind.add_tags(["phish", "x-sender-ip"])
                    if self.from_address:
                        ind.add_relationships(self.from_address)
                    self.iocs.append(ind)
                except ValueError:
                    pass
        except IndexError:
            self.x_sender_ip = ""
        
        # Find any URLs in the plaintext body.
        text_urls = RegexHelpers.find_urls(self.body)
        
        # Find any URLs in the HTML body.
        html_urls = RegexHelpers.find_urls(self.html)
            
        # Find any URLs in the visible text HTML body.
        visible_html_urls = RegexHelpers.find_urls(self.visible_html)
        
        # Make Indicators for different attachment attributes.
        strings_urls = []
        for file in self.attachments:
            if "strings_urls" in file:
                strings_urls += file["strings_urls"]
                
            # Make an Indicator for the filename.
            if file["name"]:
                try:
                    ind = Indicator.Indicator(file["name"], "Windows - FileName")
                    ind.add_tags(["phish", "attachment"])
                    if self.from_address:
                        ind.add_relationships(self.from_address)
                    if file["md5"]:
                        ind.add_relationships(file["md5"])
                    if file["sha256"]:
                        ind.add_relationships(file["sha256"])
                    self.iocs.append(ind)
                except ValueError:
                    pass
                
            # Make an Indicator for the MD5 hash.
            if file["md5"]:
                try:
                    ind = Indicator.Indicator(file["md5"], "Hash - MD5")
                    ind.add_tags(["phish", "attachment"])
                    if self.from_address:
                        ind.add_relationships(self.from_address)
                    if file["name"]:
                        ind.add_tags(file["name"])
                        ind.add_relationships(file["name"])
                    if file["sha256"]:
                        ind.add_relationships(file["sha256"])
                    self.iocs.append(ind)
                except ValueError:
                    pass
                
            # Make an Indicator for the SHA256 hash.
            if file["sha256"]:
                try:
                    ind = Indicator.Indicator(file["sha256"], "Hash - SHA256")
                    ind.add_tags(["phish", "attachment"])
                    if self.from_address:
                        ind.add_relationships(self.from_address)
                    if file["name"]:
                        ind.add_tags(file["name"])
                        ind.add_relationships(file["name"])
                    if file["md5"]:
                        ind.add_relationships(file["md5"])
                    self.iocs.append(ind)
                except ValueError:
                    pass

        # Try and remove any URLs that look like partial versions of other URLs.
        all_urls = text_urls + html_urls + visible_html_urls + strings_urls
        unique_urls = set()
        for url in all_urls:
            if not any(other_url.startswith(url) and other_url != url for other_url in all_urls):
                unique_urls.add(url)
        
        self.urls = sorted(list(unique_urls))
        
        # Now make indicators for each of the types of URLs but
        # only do so if they appear in self.urls. Doing so ensures
        # that we don't create any indicators for partial URLs.
        text_urls = [url for url in text_urls if url in self.urls]
        text_urls_indicators = Indicator.generate_url_indicators(text_urls)
        for ind in text_urls_indicators:
            ind.add_tags(["phish", "plaintext_body"])
            if self.from_address:
                ind.add_relationships(self.from_address)
            self.iocs.append(ind)
            
        html_urls = [url for url in html_urls if url in self.urls]
        html_urls_indicators = Indicator.generate_url_indicators(html_urls)
        for ind in html_urls_indicators:
            ind.add_tags(["phish", "html_body"])
            if self.from_address:
                ind.add_relationships(self.from_address)
            self.iocs.append(ind)
            
        visible_html_urls = [url for url in visible_html_urls if url in self.urls]
        visible_html_urls_indicators = Indicator.generate_url_indicators(visible_html_urls)
        for ind in visible_html_urls_indicators:
            ind.add_tags(["phish", "visible_html_body"])
            if self.from_address:
                ind.add_relationships(self.from_address)
            self.iocs.append(ind)
            
        for file in self.attachments:
            # Make Indicators for any strings URLs.
            if "strings_urls" in file:
                strings_urls = [url for url in file["strings_urls"] if url in self.urls]
                attachment_strings_urls_indicators = Indicator.generate_url_indicators(strings_urls)
                for ind in attachment_strings_urls_indicators:
                    ind.add_tags(["phish", "strings_url", file["name"]])
                    if self.from_address:
                        ind.add_relationships([self.from_address, file["name"]])
                    self.iocs.append(ind)
                        
        self.received_time = self._get_received_time()
        
        # Run the IOCs through the whitelists if requested.
        if self.whitelister and self.check_whitelist:
            self.logger.debug("Running whitelists against e-mail indicators.")
            self.iocs = Indicator.run_whitelist(self.config, self.iocs)
            
        # Finally merge the IOCs so we don't have any duplicates.
        self.iocs = Indicator.merge_duplicate_indicators(self.iocs)

    # Override __get/setstate__ in case someone
    # wants to pickle an object of this class.
    def __getstate__(self):
        d = dict(self.__dict__)
        if "logger" in d:
            del d["logger"]
        return d

    def __setstate__(self, d):
        self.__dict__.update(d)

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
                body += part.get_payload(decode=True).decode(charset, errors="ignore")
            elif part.get_content_type() == "text/html":
                html += part.get_payload(decode=True).decode(charset, errors="ignore")
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

                    try:
                        md5_hasher = hashlib.md5()
                        md5_hasher.update(file_data_decoded)
                        md5_hash = md5_hasher.hexdigest()
                    except TypeError:
                        md5_hash = ""

                    try:
                        sha256_hasher = hashlib.sha256()
                        sha256_hasher.update(file_data_decoded)
                        sha256_hash = sha256_hasher.hexdigest()
                    except TypeError:
                        sha256_hash = ""

                    attachment_dict["data"] = file_data_decoded
                    attachment_dict["content_type"] = message_part.get_content_type()
                    attachment_dict["size"] = len(file_data_decoded)
                    attachment_dict["md5"] = md5_hash
                    attachment_dict["sha256"] = sha256_hash
                    attachment_dict["name"] = ""
                    attachment_dict["create_date"] = "" 
                    attachment_dict["mod_date"] = ""
                    attachment_dict["read_date"] = ""

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
                attachment_path = ""
                
                if attachment["name"] and attachment["md5"]:
                    attachment_path = os.path.join(output_path, attachment["name"])
                elif attachment["md5"]:
                    attachment_path = os.path.join(output_path, attachment["md5"])

                if attachment_path:
                    with open(attachment_path, 'wb') as output:
                        output.write(attachment["data"])
