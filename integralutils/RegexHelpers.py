import re
import base64
import html

__email_utf8_encoded_string = re.compile(r'.*(\=\?UTF\-8\?B\?(.*)\?=).*')
__email_address = re.compile(r'[a-zA-Z0-9._%+\-"]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9_-]{2,}')
__ip = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
__domain = re.compile(r'(((?=[a-zA-Z0-9-]{1,63}\.)[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,63})')
__url = re.compile(r'(((?:(?:https?|ftp)://)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-_]*)?\??(?:[\-\+=&;%@\.\w_:\?]*)#?(?:[\.\!\/\\\w:%\?&;=-]*))?(?<!=))')
__md5 = re.compile(r'^[a-fA-F0-9]{32}$')
__sha1 = re.compile(r'^[a-fA-F0-9]{40}$')
__sha256 = re.compile(r'^[a-fA-F0-9]{64}$')
__sha512 = re.compile(r'^[a-fA-F0-9]{128}$')
__strings = re.compile(b'[^\x00-\x1F\x7F-\xFF]{4,}')

def decode_utf_b64_string(value):
    match = __email_utf8_encoded_string.match(value)
    
    if match:
        # Match the full encoded portion of the string. Ex: =?UTF-8?B?TsKqOTE4NzM4Lmh0bWw=?=
        encoded_string_full = match.group(1)
        
        # Match just the base64 portion of the string. Ex: TsKqOTE4NzM4Lmh0bWw=
        encoded_string_base64 = match.group(2)
        
        # Decode the base64.
        decoded_string_base64 = base64.b64decode(encoded_string_base64).decode("utf-8")
        
        # Set the return value equal to the original encoded value, but replace the
        # full encoded portion of the string with the decoded base64.
        return value.replace(encoded_string_full, decoded_string_base64)
    else:
        return value

def find_urls(value):
    urls = __url.findall(value)
    unescaped_urls = [html.unescape(url[0]) for url in urls]
    
    cleaned_urls = set()
    
    # Check for embedded URLs inside other URLs.
    for url in unescaped_urls:
        cleaned_urls.add(url)
        
        for chunk in url.split("http://"):
            if chunk:
                if not chunk.startswith("http://") and not chunk.startswith("https://") and not chunk.startswith("ftp://"):
                    cleaned_urls.add("http://" + chunk)

        for chunk in url.split("https://"):
            if chunk:
                if not chunk.startswith("http://") and not chunk.startswith("https://") and not chunk.startswith("ftp://"):
                    cleaned_urls.add("https://" + chunk)
                    
        for chunk in url.split("ftp://"):
            if chunk:
                if not chunk.startswith("http://") and not chunk.startswith("https://") and not chunk.startswith("ftp://"):
                    cleaned_urls.add("ftp://" + chunk)

    return sorted(list(cleaned_urls))
    
def find_strings(value):
    matches = __strings.findall(value)
    return [str(s, 'utf-8') for s in matches]

def find_ip_addresses(value):
    return __ip.findall(value)

def find_domains(value):
    return __domain.findall(value)

def is_md5(value):
    if __md5.match(value):
        return True
    else:
        return False
    
def is_sha1(value):
    if __sha1.match(value):
        return True
    else:
        return False
    
def is_sha256(value):
    if __sha256.match(value):
        return True
    else:
        return False

def is_sha512(value):
    if __sha512.match(value):
        return True
    else:
        return False

def is_ip(value):
    if __ip.match(value):
        return True
    else:
        return False