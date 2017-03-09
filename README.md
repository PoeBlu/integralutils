# integralutils
Miscellaneous helper classes and utilities used in our other programs.

## PyConfluence
PyConfluence is a Python (3.x) class for dealing with Atlassian's Confluence. It allows you to create or update pages, add labels to pages, add attachments to pages, update "sections" of a page as well as get the text of an existing page.

This is designed to run on a Linux system at this point in time.

### Confluence requirements
We currently use Confluence version 5.10.7. It is currently unknown how well this library works with other versions of Confluence.

### Example Usage
PyConfluence is simple to integrate into your own Python scripts. Edit the main integralutils config.ini file set up PyConfluence.
```
from integralutils import PyConfluence
 
confluence = PyConfluence.PyConfluence()
```

That's all it takes to get PyConfluence ready to go.

#### Create a new page
As of version 4.0, Confluence uses XHTML for the content of pages. Keep that in mind when specifying the "page_text" variable below.
```
confluence.create_page(page_title, page_text)
```
Example:
```
confluence.create_page("My new page", "Just testing my new page out.")
```

Optionally, you can create a page as a child of an existing page:
```
confluence.create_page(page_title, page_text, parent_title)
```

#### Get a page's text
```
confluence.get_page_text("My new page")
```

#### Update an existing page
Because some of the functionality provided by this library can potentially make several small API calls, it implements a caching feature. When you call the "update_page" function, you are updating your cached version of the page. You must then commit the page in order to actually send the API call to your instance of Confluence.
```
confluence.update_page("My new page", "This is the new body text of my page.")
confluence.commit_page("My new page")
```

#### Add a label to a page
```
confluence.add_page_label("My new page", "this_is_a_label")
```

#### Check if an attachment exists on a page
```
confluence.does_attachment_exist("My new page", "name_of_attachment.jpg")
```

#### Add a new attachment to a page
```
confluence.attach_file("My new page", "picture.jpg")
```

#### Update a single section on a page
Like many, we migrated from MediaWiki to Confluence. The MediaWiki markup language and its API had "section" functionality so that you could update specific parts of a page. Even though Confluence has a "section" macro you can add to a page, the API does not appear to have any built-in way to update a specific section. This function assumes that you created your page using the "create_page" function shown above (so that you have full control over the XHTML), as you need to specify the "ac:macro-id" parameter to give your section macro a descriptive name so you can refer to it later.

When you initially create your section, it should look like this in order for the "update_section" function to work:

```
<ac:structured-macro ac:name="section" ac:schema-version="1" ac:macro-id="my_custom_section"><h1>Test Section</h1>Whatever text you want inside your section.</ac:structured-macro>
```

The only other assumption is that you use a <h1-7> header tag to begin your section. This is analagous to MediaWiki's section functionality where you would define a section like "===My Section===". This allows PyConfluence to update the "body" text of the section while leaving the section "title" (your <hX> header text) unchanged.

Now that you have a section on your page named "my_custom_section", you can do the following to update only the text within that section and leave the rest of the page untouched (don't forget to commit the cached page):
```
confluence.update_section("My new page", "my_custom_section", "This is my UPDATED section text.")
confluence.commit_page("My new page")
```

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
```
# This will match any e-mail address with "@yourdomain.com" in it.
@yourdomain.com

# This will match e-mail specifically to this address.
someguy@yourdomain.com
```

Example config file for IP addresses (one regex per line):
```
# This will match an exact IP address.
127\.0\.0\.1

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