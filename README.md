# integralutils
Miscellaneous helper classes and utilities used in our other programs.

## EmailParser
Class that intelligently parses e-mails (raw email/rfc822 files or text). Key features:

*Parses common header fields like from, to, subject, message-id, etc.*

*Extracts URLs from the e-mail text and HTML bodies*

*Extracts URLs from any e-mail attachments*

*Parses e-mail attachments to get MD5/SHA256 hashes, filename, etc.*

*Optionally decodes and writes any attachments to a folder of your choice on disk*

## SandboxParser
Class that parses several different sandbox JSON reports into a consistent format.

## RegexHelpers
Various regex-related functions used in the other classes. For example, given
some text, extract any URLs from the text and check to see if there are any
valid URLs embedded within URLs.

## JsonConfigParser
Generic class primarily used with SandboxParser that takes a configurable .ini
file to know which parts of the JSON dictionary to parse out.