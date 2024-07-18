###
# URL decoding mini library.  
# The purpose of this script is to manage URLs embedded in emails and
# .ics calendar events.  The idea is to decode URLs that have been
# wrapped by Outlook safelinks, proofpoint, etc.
# I also wrote a wrapper to an API to shorten URLs. 
###



import re
import sys
import urllib.parse
import urllib.request
import io
import string
import os
import csv
import yaml

from base64 import b64encode

from base64 import urlsafe_b64decode
if sys.version_info[0] < 3:
    from urllib import unquote
    import HTMLParser
    htmlparser = HTMLParser.HTMLParser()
    unescape = htmlparser.unescape
    from string import maketrans
else:
    from urllib.parse import unquote
    from html import unescape
    maketrans = str.maketrans

# you must provide a way for this script to shorten URLs
# this could be something like tinyurl (where you would put in the API
# endpoint for creating URLs), though you may have to edit how the
# authorization token gets sent.  
class ShortUrlCfg:
    def __init__(self):
        self.URL_CREATE_ENDPOINT = ""   # endpoint for new shortened URL
        self.URL_AUTHORIZATION = ""     # authorization information (e.g., bearer token)
        self.URL_SHORTEN_PREFIX = ""    # server name of shortening service 
        self.URL_SHORTEN_ENDPOINT = ""  # endpoint for accessing the shortened URL
 

cfg = ShortUrlCfg()

# load config
with open("config.yaml") as f:
    config = yaml.load(f)
    cfg.URL_CREATE_ENDPOINT = config.short_url_create_endpoint
    cfg.URL_AUTHORIZATION = config.short_url_create_authorization
    cfg.URL_SHORTEN_PREFIX = config.short_url_prefix
    cfg.URL_SHORTEN_ENDPOINT = config.short_url_endpoint


# map original url to URL_SHORTEN_PREFIX url
cached_urls = {}
# inverse mapping...
uncached_urls = {}
cache_file = os.path.expanduser('~')
cache_file = os.path.join( cache_file, '.urlcache' )
with open(cache_file, 'r') as f:
    reader = csv.reader(f)

    for row in reader:
        url = row[0]
        shortened = row[1]

        if not url in cached_urls.keys():
            cached_urls[url] = shortened
            uncached_urls[shortened] = url

def uncached_url(url):
    global cache_file, uncached_urls
    if not url in uncached_urls.keys():
        return False
    else:
        return uncached_urls[url]



def cached_url(url):
    global cache_file, cached_urls

    # return false if we can't find the given URL
    if not url in cached_urls.keys():
        return False
    else:
        # if we do find it, return the shortened URL
        return cached_urls[url]

def commit_to_cache(url, shorturl):
    global cached_urls, cache_file

    if not url in cached_urls.keys():
        cached_urls[url] = shorturl
        uncached_urls[shorturl] = url
        with open(cache_file, 'a') as f:
            w = csv.writer(f)
            w.writerow([url, shorturl])

def get_shortened(url):
    global cfg
    if not cached_url(url):
        shorturl_req = urllib.request.Request(
            cfg.URL_CREATE_ENDPOINT+url
        )
        shorturl_req.add_header(
            'Authorization', 'Basic {}'
            .format(
                b64encode(
                cfg.URL_AUTHORIZATION
                 .encode('ascii')
                ).decode()
            )
        )

        shorturl = urllib.request.urlopen(
            shorturl_req
        ).read().decode()
        
        if shorturl.startswith(cfg.URL_SHORTEN_PREFIX):
            commit_to_cache(url, shorturl)
            return shorturl
        else:
            return False

    else:
        return cached_url(url)


#taken from https://files.mtstatic.com/site_6638/draft_2775/0?Expires=1721328944&Signature=MB6ZP1dqTskogesN6KPxfKxk4O8w2r0DMAcKiHOW8u4a62L3QxtaBCO6EzgXbb8Gb18lz23Pn8CwQjjVNFfpMPfMkCLAy6Iz0hsaq3JQKJ8ZCra4gqje7RUgvd7sGBfnFPRIsElIHvVg0WqC3FgF1LQNv9sUNUMFLY92cfDHmdU_&Key-Pair-Id=APKAJ5Y6AV4GI7A555NA

class URLDefenseDecoder(object):

    @staticmethod
    def __init__():
        URLDefenseDecoder.ud_pattern = re.compile(r'https://urldefense(?:\.proofpoint)?\.com/(v[0-9])/')
        URLDefenseDecoder.v1_pattern = re.compile(r'u=(?P<url>.+?)&k=')
        URLDefenseDecoder.v2_pattern = re.compile(r'u=(?P<url>.+?)&[dc]=')
        URLDefenseDecoder.v3_pattern = re.compile(r'v3/__(?P<url>.+?)__;(?P<enc_bytes>.*?)!')
        URLDefenseDecoder.v3_token_pattern = re.compile(r"\*(\*.)?")
        URLDefenseDecoder.v3_single_slash = re.compile(r"^([a-z0-9+.-]+:/)([^/].+)", re.IGNORECASE)
        URLDefenseDecoder.v3_run_mapping = {}
        run_values = string.ascii_uppercase + string.ascii_lowercase + string.digits + '-' + '_'
        run_length = 2
        for value in run_values:
            URLDefenseDecoder.v3_run_mapping[value] = run_length
            run_length += 1

    def decode(self, rewritten_url):
        match = self.ud_pattern.search(rewritten_url)
        if match:
            if match.group(1) == 'v1':
                return self.decode_v1(rewritten_url)
            elif match.group(1) == 'v2':
                return self.decode_v2(rewritten_url)
            elif match.group(1) == 'v3':
                return self.decode_v3(rewritten_url)
            else:
                raise ValueError('Unrecognized version in: ', rewritten_url)
        else:
            raise ValueError('Does not appear to be a URL Defense URL')

    def decode_v1(self, rewritten_url):
        match = self.v1_pattern.search(rewritten_url)
        if match:
            url_encoded_url = match.group('url')
            html_encoded_url = unquote(url_encoded_url)
            url = unescape(html_encoded_url)
            return url
        else:
            raise ValueError('Error parsing URL')

    def decode_v2(self, rewritten_url):
        match = self.v2_pattern.search(rewritten_url)
        if match:
            special_encoded_url = match.group('url')
            trans = maketrans('-_', '%/')
            url_encoded_url = special_encoded_url.translate(trans)
            html_encoded_url = unquote(url_encoded_url)
            url = unescape(html_encoded_url)
            return url
        else:
            raise ValueError('Error parsing URL')

    def decode_v3(self, rewritten_url):
        def replace_token(token):
            if token == '*':
                character = self.dec_bytes[self.current_marker]
                self.current_marker += 1
                return character
            if token.startswith('**'):
                run_length = self.v3_run_mapping[token[-1]]
                run = self.dec_bytes[self.current_marker:self.current_marker + run_length]
                self.current_marker += run_length
                return run

        def substitute_tokens(text, start_pos=0):
            match = self.v3_token_pattern.search(text, start_pos)
            if match:
                start = text[start_pos:match.start()]
                built_string = start
                token = text[match.start():match.end()]
                built_string += replace_token(token)
                built_string += substitute_tokens(text, match.end())
                return built_string
            else:
                return text[start_pos:len(text)]

        match = self.v3_pattern.search(rewritten_url)
        if match:
            url = match.group('url')
            singleSlash = self.v3_single_slash.findall(url)
            if singleSlash and len(singleSlash[0]) == 2:
                url = singleSlash[0][0] + "/" + singleSlash[0][1]
            encoded_url = unquote(url)
            enc_bytes = match.group('enc_bytes')
            enc_bytes += '=='
            self.dec_bytes = (urlsafe_b64decode(enc_bytes)).decode('utf-8')
            self.current_marker = 0
            return substitute_tokens(encoded_url)

        else:
            raise ValueError('Error parsing URL')

def decode_url(url):
    global cfg
    url_parts = url.split('?')[1]
    params = url_parts.split('&')
    
    target_url = '### UNKNOWN SAFELINKS URL ###'
    for i in params:
        name, val = i.split('=')
        if name == 'url':
            target_url = urllib.parse.unquote(val)

    return target_url

def rewrite_urls(input_str, encoding='utf-8'):
#for line in f:
    results = re.findall(r'((http|ftp|https):\/\/([\w\-_]+(?:(?:\.[\w\-_]+)+))([\w\-\.,!@?^=%&:/~\+#;]*[\w\-\!@?^=%&/~\+#;])?)', input_str)

    output_line = input_str 
    if len(results) > 0:
        for x in results:
            # for a safelinks protected URL, make sure safelinks is
            # at the start (i.e., before the query string)
            if '?url' in x[0] and 'safelinks' in x[0].split('?url')[0]:
                # basically set up a loop to keep decoding URLs (it
                # might have been wrapped by safelinkes, then
                # urldefender, etc.)
                linkProtectorRemaining = True
                newlink = decode_url(x[0])

                while linkProtectorRemaining:
                    if 'urldefense' in newlink and newlink.startswith('https://urldefense'):
                        newlink_decoder = URLDefenseDecoder()
                        newlink = newlink_decoder.decode(newlink)
                   
                    output_line = output_line.rstrip().replace(x[0], newlink)

                    # assume we're done first
                    linkProtectorRemaining = False
                    # but if any of these remain in the URL...
                    for linkprotector in ['urldefense']:
                        if linkprotector in newlink:
                            # ... then make us keep going
                            linkProtectorRemaining = True
         
        # do it again, but shorten URLs...
        results = re.findall(r'((http|ftp|https):\/\/([\w\-_]+(?:(?:\.[\w\-_]+)+))([\w\-\.,!@?^=%&:/~\+#;]*[\w\-\!@?^=%&/~\+#;])?)', output_line)

        for x in results:
            if len(x[0]) > 50 and not cfg.URL_SHORTEN_ENDPOINT in x[0]:
                
                shorturl = get_shortened(x[0])

                if shorturl != False and shorturl.startswith(cfg.URL_SHORTEN_PREFIX):
                    output_line = output_line.rstrip().replace(
                        x[0], shorturl + " (" + x[0] + ")"
                    )
    
    return output_line.rstrip()



def shorten_invite(input_str, encoding='utf-8'):
    # For calendar invites, there may be a very long string with a lot
    # of details that aren't necessary in something like khal.
    # this script goes through the input string and rewrites contents
    # focusing only on meeting links that it finds (Zoom, Teams, etc.). 

    ret = set()

    zoom_regex = r'(https:\/\/[\w-]*\.?zoom(gov.com|.us)\/(j|my)\/[\d\w?=-]+)'
    teams_regex = r'(https:\/\/(gov\.teams|teams).microsoft(.com|.us)\/(l)\/meetup-join\/[%\.\/\d\w?=-]+)'
    meet_regex = r'(https:\/\/meet.google.com\/[a-z]{3}-[a-z]{4}-[a-z]{3})'


    zoomlinks = re.findall(zoom_regex, input_str)

    for x in zoomlinks:
        target_url = ''
        if isinstance(x, str):
            target_url = x
        elif isinstance(x, tuple):
            target_url = x[0]

        s = get_shortened(target_url)
        if s == False:
            s = target_url


        ret.add('Zoom: ' + s)


    teamslinks = re.findall(teams_regex, input_str)

    for x in teamslinks:
        target_url = ''
        if isinstance(x, str):
            target_url = x
        elif isinstance(x, tuple):
            target_url = x[0]

        s = get_shortened(target_url)
        if s == False:
            s = target_url


        ret.add('Teams: ' + s)


    meetlinks = re.findall(meet_regex, input_str)

    for x in meetlinks:
        target_url = ''
        if isinstance(x, str):
            target_url = x
        elif isinstance(x, tuple):
            target_url = x[0]

        s = get_shortened(target_url)
        if s == False:
            s = target_url


        ret.add('Meet: ' + s)

    if len(ret) == 0:
        return False
    else:
        return ', '.join(ret)


def extract_urls(input_str, _link_counter = 1):
    #ret = set()
    ret = []
    big = {}
    link_counter = _link_counter
    output_str = input_str

    results = re.findall(r'((http|ftp|https):\/\/([\w\-_]+(?:(?:\.[\w\-_]+)+))([\w\-\.,!@?^=%&:/~\+#;]*[\w\-\!@?^=%&/~\+#;])?)', input_str)
    
    if len(results) > 0:
        for link in results:
            link = link if isinstance(link, str) else link[0]
            
            # provide a hint for the URL if it's already been cached...
            if not link in ret:
                if link in big.keys():
                    continue
                # one of these will be false.

                # ps will be False if link contains the
                # URL_SHORTEN_PREFIX or has not been shortened
                ps = cached_url(link) 

                # pu will be False if link has not been shortened.
                pu = uncached_url(link)

                # if ps is _not_ false, it means link contains an
                # original URL that was shortened to whatever ps is

                # if pu is _not_ false, it means link contains a
                # shortened URL_SHORTEN_PREFIX URL and that the
                # unshortened version is whateever is in pu

                # if both ps and pu are false, it means it's just a
                # random link that underwent no shortening

                if pu == False and ps == False:
                    ret.append('[{}] {}'.format(link_counter, link))
                    output_str = output_str.replace(link, 
                        '[{}] {}'.format(link_counter, link)
                    )

                    big[link] = link_counter
                    link_counter += 1
                else:
                    
                    unshortened = None
                    shortened = None

                    if pu != False and ps == False:
                        shortened = link
                        unshortened = pu
                    elif pu == False and ps != False:
                        shortened = ps
                        unshortened = link
                    else:
                        # there's a problem... just continue I guess
                        continue

                    format_unshortened = unshortened
                    if len(unshortened) > 40:
                        format_unshortened = unshortened[8:28] + '...' + unshortened[-10:]

                    ret.append('[{}] {} ({})'.format(
                        link_counter,
                        shortened,
                        format_unshortened)
                    )
            
                    output_str = output_str.replace(shortened,
                        '[{}] {}'.format(link_counter, shortened)
                    )
                    output_str = output_str.replace(unshortened,
                        '[{}] {}'.format(link_counter, unshortened)
                    )

                    big[shortened] = link_counter
                    big[unshortened] = link_counter
                    link_counter += 1

    return (ret, output_str)




