# integralutils
Miscellaneous helper classes and utilities used in our other programs.

## Indicator
Class that models CRITS indicators. Instances of this class can contain an indicator value, tags, relationships, etc.

Other features include:

-- *Generate a list of Indicator objects from a list of URLs.*

-- *Return a list of Indicator objects after running them against your whitelists.*

-- *Write a list of Indicator objects to a CSV file for easier importing into CRITS.*

-- *Read an existing CSV file and parse it into Indicator objects.*

-- *Append a list of Indicator objects to an existing CSV file.*

-- *Accept a list of Indicator objects and merge duplicates, thus merging their tags and relationships.*

Example usage:

```python
from integralutils import Indicator

indicator_list = []
ind1 = Indicator.Indicator("somebaddomain.com", "URI - Domain Name")
ind1.add_tags("blah")
ind1.add_tags(["something", "something_else"])
ind1.add_relationships("someotherbaddomain.com")
ind1.add_relationships(["yetanotherdomain.com", "some_other_indicator"])

indicator_list.append(ind1)

ind2 = Indicator.Indicator("somebaddomain.com", "URI - Domain Name")
ind2.add_tags("a_new_tag")

indicator_list.append(ind2)

merged_indicators = Indicator.merge_duplicate_indicators(indicator_list)
print(len(merged_indicators))
print(merged_indicators[0].indicator)
print(merged_indicators[0].tags)
```

## EmailParser
Class that intelligently parses e-mails (raw email/rfc822 files or text). Key features:

-- *Generates CRITS-style indicators from various header fields and attachment characteristics.*

-- *Runs the indicators through your whitelists to remove any bad indicators.*

-- *Parses common header fields like from, to, subject, message-id, etc.*

-- *Extracts "visible text" from HTML e-mail body to help with span/div obfuscated HTML.*

-- *Extracts URLs from the e-mail text and HTML bodies.*

-- *Extracts URLs from any e-mail attachments.*

-- *Parses e-mail attachments to get MD5/SHA256 hashes, filename, etc.*

-- *Optionally decodes and writes any attachments to a folder of your choice on disk.*

Example usage:

```python
from integralutils import EmailParser

parsed_email = EmailParser.EmailParser(smtp_path="/path/to/email.smtp")
for ioc in parsed_email.iocs:
    print(ioc.indicator + " - " + ioc.type)
    print(ioc.tags)
    print(ioc.relationships)
```

**By default the EmailParser class will take advantage of the Whitelist class
and the various whitelists that you configure it to use.**

## Whitelist
Class that has various whitelist/benignlist functionality. You specify in the config
file the paths to your various whitelists. The functions in the Whitelist class expect
the lines in your whitelist files to be valid regex statements since they rely on the
re.search() function.

Your whitelist files can have comments in them if the lines begin with the "#" character.

Example config file for e-mail addresses (one regex per line):
```python
@yourdomain.com
someguy@yourdomain.com
```

Example config file for IP addresses (one regex per line):
```python
127.0.0.1
# Private RFC 1918 addresses
10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}
172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}
192\.168\.[0-9]{1,3}\.[0-9]{1,3}
```

## SandboxParser
Class that parses several different sandbox JSON reports into a consistent format.

## RegexHelpers
Various regex-related functions used in the other classes. For example, given
some text, extract any URLs from the text and check to see if there are any
valid URLs embedded within URLs.

## JsonConfigParser
Generic class primarily used with SandboxParser that takes a configurable .ini
file to know which parts of the JSON dictionary to parse out.