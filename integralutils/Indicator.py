import csv
import os
import re
import configparser
from urllib.parse import urlsplit

from integralutils import RegexHelpers
from integralutils import Whitelist

class Indicator:
    # This class is modeled after a CRITS indicator and the .csv file you could create to upload new indicators into CRITS.
    # For example, the .csv file might look something like this when using this class:
    #
    # Indicator,Type,Threat Type,Attack Type,Description,Campaign,Campaign Confidence,Confidence,Impact,Bucket List,Ticket,Action
    # 18d4695d8ebd3d7d6df1c7a8fdcbd64d,Hash - MD5,,,,,,low,low,"dropped_file,somefile.exe,ransomware",,
    indicator_csv_header = ["Indicator", "Type", "Threat Type", "Attack Type", "Description", "Campaign", "Campaign Confidence", "Confidence", "Impact", "Bucket List", "Ticket", "Action"]

    def __init__(self, indicator, type, check_whitelist=True):
        if not isinstance(indicator, str):
            raise ValueError("indicator must be a string")
        if not indicator:
            raise ValueError("indicator cannot be a blank string")
        
        self._indicator = indicator
        self._type = type
        self.threat_type = ""
        self.attack_type = ""
        self.description = ""
        self.campaign = ""
        self.campaign_conf = ""
        self.conf = "low"
        self.impact = "low"
        self._tags = set()
        self.ticket = ""
        self.action = ""
        self._relationships = set()

    def __eq__(self, other):
        if isinstance(other, Indicator):
            return (self.indicator == other.indicator) and (self.type == other.type)
        else:
            return False
            
    def __hash__(self):
        return hash((self.indicator, self.type))
        
    @property
    def indicator(self):
        return self._indicator
        
    @property
    def type(self):
        return self._type
        
    @property
    def tags(self):
        return sorted(list(self._tags))
        
    @property
    def relationships(self):
        return sorted(list(self._relationships))

    def add_tags(self, tags):
        if isinstance(tags, str):
            # Make sure we don't add a blank string.
            if tags:
                self._tags.add(tags)
        elif isinstance(tags, list) or isinstance(tags, set):
            for string in tags:
                # Make sure we don't add a blank string.
                if string:
                    self._tags.add(string)
        else:
            raise ValueError("add_tags requires a string or a list of strings")
            
    def add_relationships(self, relationships):
        # If we're adding a single relationship (a string), add it
        # to a list anyway so that we can treat things uniformly.
        if isinstance(relationships, str):
            relationships = [relationships]
            
        # Make sure we're dealing with a list.
        if not isinstance(relationships, list):
            raise ValueError("add_relationships requires a string or a list of strings")
        
        # Make sure that each relationship in the list is a string.
        if all(isinstance(rel, str) for rel in relationships):
            for rel in relationships:
                # Make sure we don't add a blank relationship.
                if rel:
                    # Make sure we don't add a relationship to ourselves.
                    if rel != self.indicator:
                        self._relationships.add(rel)
        else:
            raise ValueError("each relationship needs to be a string")
            
    def benign(self):
        self.conf = "benign"
        self.impact = "benign"

    def csv_line(self):
        # Convert the set of tags to a string.
        if self.tags:
            tag_string = ",".join(self.tags)
        else:
            tag_string = ""
            
        return [self.indicator, self.type, self.threat_type, self.attack_type, self.description, self.campaign, self.campaign_conf, self.conf, self.impact, tag_string, self.ticket, self.action]

def run_whitelist(indicator_list, config_path=None):
    # Make sure we are dealing with a list of Indicator objects.
    if all(isinstance(indicator, Indicator) for indicator in indicator_list):
        # If we weren't given a config_path, assume we're loading
        # the one shipped with integralutils.
        if not config_path:
            config_path = os.path.join(os.path.dirname(__file__), "etc", "Indicator.ini")
            
        # Lists to hold the good (non-whitelisted or benign) indicators
        # as well as bad (whitelisted) indicators. The bad indicator list is
        # used at the end to cross-check any relationships in the good indicator
        # list so we can remove them as well.
        good_indicators = []
        bad_indicators = []
        
        # Read the config file and get the Indicator whitelist/benignlist directory.
        config = configparser.ConfigParser()
        config.read(config_path)
        indicator_whitelist_dir = config["Directories"]["whitelist_dir"]
        indicator_benignlist_dir = config["Directories"]["benignlist_dir"]
        
        # List the whitelist directory to see which whitelists we have.
        indicator_type_whitelist_files = os.listdir(indicator_whitelist_dir)

        # Keep a dictionary of all of the available whitelists.
        available_whitelists = {}
        for indicator_type in indicator_type_whitelist_files:
            with open(os.path.join(indicator_whitelist_dir, indicator_type)) as w:
                lines = w.read().splitlines()
                        
                # Remove any lines that begin with #.
                lines = [line for line in lines if not line.startswith("#")]

                # Remove any blank lines.
                lines = [line for line in lines if line]
                
                # Store the regex lines in the dictionary.
                available_whitelists[indicator_type] = lines

        # List the benignlist directory to see which benignlists we have.
        indicator_type_benignlist_files = os.listdir(indicator_benignlist_dir)
                      
        # Keep a dictionary of all of the available benignlists.
        available_benignlists = {}
        for indicator_type in indicator_type_benignlist_files:
            with open(os.path.join(indicator_benignlist_dir, indicator_type)) as b:
                lines = b.read().splitlines()
                        
                # Remove any lines that begin with #.
                lines = [line for line in lines if not line.startswith("#")]

                # Remove any blank lines.
                lines = [line for line in lines if line]
                
                # Store the regex lines in the dictionary.
                available_benignlists[indicator_type] = lines
        
        # Loop over each indicator in the list and see if we have a
        # whitelist or benignlist to run against it.
        for ind in indicator_list:
            # Check if we loaded a benignlist for this indicator type.
            if ind.type in available_benignlists:
                # Now check if the indicator is actually benign.
                for regex in available_benignlists[ind.type]:
                    pattern = re.compile(regex)
                    if pattern.search(ind.indicator):
                        ind.benign()

            # Check if we loaded a whitelist for this indicator type.
            if ind.type in available_whitelists:
                # Assume the indicator is not whitelisted to start.
                good_indicators.append(ind)
                
                # Now check if the indicator is actually whitelisted.
                for regex in available_whitelists[ind.type]:
                    pattern = re.compile(regex)
                    # If the regex matched, add the indicator to the
                    # bad list, and remove it from the good list.
                    if pattern.search(ind.indicator):
                        bad_indicators.append(ind)
                        try:
                            good_indicators.remove(ind)
                        except ValueError:
                            pass

            # There isn't a whitelist for this indicator type. Just assume it's good.
            else:
                good_indicators.append(ind)

        # Now loop through the bad indicator list to see if any of
        # these indicators have relationships with any indicators that we
        # determined were good. If so, we should treat those indicators as
        # also being bad. For example, if we have a URL indicator (and thus
        # also a domain name and URI path indicator), but the domain is
        # whitelisted, we assume we don't want to bother adding the URI
        # path or the URL as an indicator.
        for bad_indicator in bad_indicators:
            # Iterate over a copy of the good_indicators list so that
            # we can remove elements from the actual list at the same time.
            for good_indicator in good_indicators[:]:
                if bad_indicator.indicator in good_indicator.relationships:
                    good_indicators.remove(good_indicator)

        return good_indicators

def read_relationships_csv(csv_path):
    # Use a set instead of a list so we weed out any duplicates.
    relationships = set()

    # A "normal" relationship in the file should look like:
    #
    # something,something_else
    with open(csv_path) as c:
        csv_reader = csv.reader(c)

        # Unlike the indicators .csv file, there is no header to skip.
        for relationship in csv_reader:
            # Skip any malformed lines.
            if len(relationship) == 2:
                relationships.add((relationship[0], relationship[1]))

    return sorted(list(relationships))

def write_relationships_csv(indicator_list, csv_path, append=True, whitelist=True, merge=True):
    # Make sure we are dealing with a list of Indicator objects.
    if all(isinstance(indicator, Indicator) for indicator in indicator_list):
        if whitelist:
            indicator_list = run_whitelist(indicator_list)
        
        new_relationships = get_unique_relationships(indicator_list)
        
        if os.path.exists(csv_path):
            existing_relationships = read_relationships_csv(csv_path)
        else:
            existing_relationships = []

        if append:
            new_relationships += existing_relationships

        if merge:
            new_relationships = merge_duplicate_relationships(existing_relationships, new_relationships)

        with open(csv_path, "w", newline="") as c:
            csv_writer = csv.writer(c)

            for relationship in new_relationships:
                csv_writer.writerow(relationship)

def read_indicators_csv(csv_path, merge=True):
    indicators = []

    with open(csv_path) as c:
        csv_reader = csv.reader(c)

        # Skip over the CSV header row.
        next(csv_reader, None)

        # Make sure this line in the file has the right number of values.
        for indicator in csv_reader:
            if len(indicator) == len(Indicator.indicator_csv_header):
                indicator_value = indicator[0]
                indicator_type = indicator[1]
                threat_type = indicator[2]
                attack_type = indicator[3]
                description = indicator[4]
                campaign = indicator[5]
                campaign_conf = indicator[6]
                conf = indicator[7]
                impact = indicator[8]
                tags = indicator[9]
                ticket = indicator[10]
                action = indicator[11]

                new_indicator = Indicator(indicator_value, indicator_type)
                new_indicator.threat_type = threat_type
                new_indicator.attack_type = attack_type
                new_indicator.description = description
                new_indicator.campaign = campaign
                new_indicator.campaign_conf = campaign_conf
                new_indicator.conf = conf
                new_indicator.impact = impact
                new_indicator.add_tags(tags.split(","))
                new_indicator.ticket = ticket
                new_indicator.action = action

                indicators.append(new_indicator)

    if merge:
        return merge_duplicate_indicators(indicators)
    else:
        return indicators

def write_indicators_csv(indicator_list, csv_path, append=True, whitelist=True, merge=True):
    # Make sure we are dealing with a list of Indicator objects.
    if all(isinstance(indicator, Indicator) for indicator in indicator_list):            
        if os.path.exists(csv_path):
            existing_indicators = read_indicators_csv(csv_path)
        else:
            existing_indicators = []
            
        if append:
            indicator_list += existing_indicators

        if merge:
            indicator_list = merge_duplicate_indicators(indicator_list)
            
        if whitelist:
            indicator_list = run_whitelist(indicator_list)

        with open(csv_path, "w", newline="") as c:
            csv_writer = csv.writer(c)
            csv_writer.writerow(Indicator.indicator_csv_header)

            for indicator in indicator_list:
                csv_writer.writerow(indicator.csv_line())

def get_indicators_with_tag(tag, indicator_list):
    # Make sure we are dealing with a list of Indicator objects.
    if all(isinstance(indicator, Indicator) for indicator in indicator_list):
        return [indicator for indicator in indicator_list if tag in indicator.tags]
    else:
        raise ValueError("get_indicators_with_tag requires a list of Indicator objects")

def get_indicators_with_value(value, indicator_list):
    # Make sure we are dealing with a list of Indicator objects.
    if all(isinstance(indicator, Indicator) for indicator in indicator_list):
        return [indicator for indicator in indicator_list if value in indicator.indicator]
    else:
        raise ValueError("get_indicators_with_value requires a list of Indicator objects")

def get_unique_relationships(indicator_list):
    # Make sure we are dealing with a list of Indicator objects.
    if all(isinstance(indicator, Indicator) for indicator in indicator_list):
        working_list = []
        # Since self.relationships is just a list of strings, the
        # implied relationship is between each of those strings and
        # whatever the value is for self.indicator.
        for indicator in indicator_list:
            for relationship in indicator.relationships:
                rel = (indicator.indicator, relationship)
                rel_reversed = rel[::-1]
                if not rel in working_list and not rel_reversed in working_list:
                    working_list.append(rel)
        return working_list
    else:
        raise ValueError("get_unique_relationships requires a list of Indicator objects")

def merge_duplicate_relationships(rel_a, rel_b):
    working_list = []

    for rel in rel_a + rel_b:
        rel_reversed = rel[::-1]
        if not rel in working_list and not rel_reversed in working_list:
            working_list.append(rel)

    return working_list

def merge_duplicate_indicators(indicator_list):
    # Make sure we are dealing with a list of Indicator objects.
    if all(isinstance(indicator, Indicator) for indicator in indicator_list):
        working_list = []
        for indicator in indicator_list:
            # If we found the indicator in our temporary list, pop
            # it out, merge the tags/relationships, and add it back in.
            if indicator in working_list:
                existing_indicator_index = working_list.index(indicator)
                existing_indicator = working_list.pop(existing_indicator_index)
                indicator.add_tags(existing_indicator.tags)
                indicator.add_relationships(existing_indicator.relationships)
                working_list.append(indicator)
            else:
                working_list.append(indicator)
        return working_list
    else:
        raise ValueError("merge_duplicate_indicators requires a list of Indicator objects")
        
def generate_url_indicators(url_list):
    indicators = []
        
    # Parse the URLs so that we can create Indicators and also prevent
    # "duplicate" URLs like http://blah.com/ and http://blah.com
    for url in url_list:
        if RegexHelpers.is_url(url):
            # Strip off the ending slash if it's there.
            if url.endswith("/"):
                url = url[:-1]

            parsed_url = urlsplit(url)

            # Is the netloc an IP address?
            if RegexHelpers.is_ip(parsed_url.netloc):
                netloc_type = "Address - ipv4-addr"
            # If the netloc is not an IP, it must be a domain.
            else:
                netloc_type = "URI - Domain Name"

            # Make an Indicator for the URI host.
            try:
                ind = Indicator(parsed_url.netloc, netloc_type)
                ind.add_tags("uri_host")
                ind.add_relationships(url)
                indicators.append(ind)
            except ValueError:
                pass

            # Make an Indicator for the full URL.
            try:
                ind = Indicator(url, "URI - URL")
                ind.add_relationships(parsed_url.netloc)
                indicators.append(ind)
            except ValueError:
                pass

            # Make an Indicator for the path (if there is one).
            if parsed_url.path and parsed_url.path != "/":
                try:
                    # Check if there were any ? query items.
                    if parsed_url.query:
                        uri_path = parsed_url.path + "?" + parsed_url.query
                    else:
                        uri_path = parsed_url.path
                        
                    ind = Indicator(uri_path, "URI - Path")
                    ind.add_tags(["uri_path", parsed_url.netloc])
                    ind.add_relationships([url, parsed_url.netloc])
                    indicators.append(ind)
                except ValueError:
                    pass

    return indicators