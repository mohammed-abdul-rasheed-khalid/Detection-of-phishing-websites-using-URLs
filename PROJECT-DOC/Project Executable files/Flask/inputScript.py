import tldextract
import pandas as pd
import numpy as np
import re
import urllib
from datetime import date, datetime
from bs4 import BeautifulSoup

def having_IP_Address(url):
    match = re.search(
        '(([0-9]{1,3}\.){3}[0-9]{1,3})|([0-9a-fA-F]{1,4}:{1,4}:{1,4}:{1,4}:{1,4}:{1,4}:{1,4}:{1,4})',
        url)
    if match:
        return -1
    else:
        return 1

def URL_Length(url):
    if len(url) < 54:
        return 1
    elif len(url) >= 54 and len(url) <= 75:
        return 0
    else:
        return -1

def Shortining_Service(url):
    match = re.search(
        'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t2m\.io|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|xurl\.es|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
        url)
    if match:
        return -1
    else:
        return 1

def having_At_Symbol(url):
    if '@' in url:
        return -1
    else:
        return 1

def double_slash_redirecting(url):
    list = [x.start(0) for x in re.finditer('//', url)]
    if list[len(list) - 1] > 6:
        return -1
    else:
        return 1

def Prefix_Suffix(url):
    if '-' in url:
        return -1
    else:
        return 1

def having_Sub_Domain(url):
    if url.count('.') == 1:
        return 1
    elif url.count('.') == 2:
        return 0
    else:
        return -1

def SSLfinal_State(url):
    try:
        if re.search('^https', url):
            usehttps = 1
        else:
            usehttps = 0
        subDomain, domain, suffix = tldextract.extract(url)
        host_name = domain + '.' + suffix
        context = ssl.create_default_context()
        sct = context.wrap_socket(socket.socket(), server_hostname=host_name)
        sct.connect((host_name, 443))
        certificate = sct.getpeercert()
        issuer = dict(x[0] for x in certificate['issuer'])
        certificate_Auth = str(issuer['organizationName'])
        certificate_Auth = certificate_Auth.split()
        if certificate_Auth[0] == 'GeoTrust' or certificate_Auth == 'GoDaddy' or certificate_Auth == 'Network' or certificate_Auth == 'Solutions' or certificate_Auth == 'Thawte' or certificate_Auth == 'Doster' or certificate_Auth == 'VeriSign' or certificate_Auth == 'LinkedIn' or certificate_Auth == 'Facebook' or certificate_Auth == 'Comodo' or certificate_Auth == 'Starfield' or certificate_Auth == 'Global' or certificate_Auth == 'DigiCert':
            certificate_Auth = certificate_Auth[0]
        else:
            certificate_Auth = certificate_Auth[0] + ' ' + certificate_Auth[1]
        startingDate = str(certificate['notBefore'])
        endingDate = str(certificate['notAfter'])
        startingYear = int(startingDate.split()[3])
        endingYear = int(endingDate.split()[3])
        Age_of_certificate = endingYear - startingYear

        if (usehttps == 1) and (certificate_Auth in trusted_CAs) and (Age_of_certificate >= 1):
            return 1
        elif (usehttps == 1) and (certificate_Auth not in trusted_CAs):
            return 0
        else:
            return -1

    except Exception as e:
        return -1

def Domain_registeration(url):
    try:
        w = whois.whois(url)
        updated = w.updated_date
        exp = w.expiration_date
        length = (exp[0] - updated[0]).days
        if length <= 365:
            return -1
        else:
            return 1
    except:
        return -1

def Favicon(url):
    try:
        favicon = []
        parsed_url = urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        soup = BeautifulSoup(urllib.request.urlopen(url), 'html.parser')
        for link in soup.find_all('link', rel='icon'):
            favicon.append(link.get('href'))
        for fav in favicon:
            if base_url not in fav:
                return -1
        return 1
    except:
        return -1

def port(url):
    try:
        domain = whois.whois(url)
        open_ports = [port.port for port in domain.get_open_ports()]
        if len(open_ports) == 0:
            return 1
        else:
            return -1
    except:
        return -1

def HTTPS_token(url):
    if re.search('https|http', url):
        return -1
    else:
        return 1

def Request_URL(url):
    try:
        domain_name = re.findall(r'www\.|https:|http:', url)
        soup = BeautifulSoup(urllib.request.urlopen(url), 'html.parser')
        for img in soup.find_all('img', src=True):
            dots = [x.start(0) for x in re.finditer('\.', img['src'])]
            if url in img['src'] or len(dots) == 1:
                return 1
            else:
                return -1
    except:
        return -1

def URL_of_Anchor(url):
    try:
        domain_name = re.findall(r'www\.|https:|http:', url)
        soup = BeautifulSoup(urllib.request.urlopen(url), 'html.parser')
        unsafe = 0
        for a in soup.find_all('a', href=True):
            if '#' in a['href'] or 'javascript' in a['href'].lower() or 'mailto' in a['href'].lower() or not a['href']:
                unsafe += 1
        total = len(soup.find_all('a', href=True))
        return unsafe / total
    except:
        return -1

def Links_in_tags(url):
    try:
        soup = BeautifulSoup(urllib.request.urlopen(url), 'html.parser')
        meta = len(soup.find_all('meta', content=True))
        link = len(soup.find_all('link', href=True))
        script = len(soup.find_all('script', src=True))
        tags = meta + link + script
        if tags == 0:
            return 1
        elif tags <= 10:
            return 0
        else:
            return -1
    except:
        return -1

def SFH(url):
    try:
        soup = BeautifulSoup(urllib.request.urlopen(url), 'html.parser')
        if soup.find('form'):
            form = soup.find('form')
            action = form.get('action')
            if action == '':
                return 1
            elif 'about:blank' in action:
                return -1
            elif 'https' in action or 'http' in action:
                return 0
            else:
                return 1
    except:
        return -1

def Submitting_to_email(url):
    try:
        soup = BeautifulSoup(urllib.request.urlopen(url), 'html.parser')
        if soup.find('mailto:'):
            return -1
        else:
            return 1
    except:
        return -1

def Abnormal_URL(url):
    try:
        w = whois.whois(url)
        hostname = w.domain_name
        if hostname in url:
            return 1
        else:
            return -1
    except:
        return -1

def Redirect(url):
    try:
        soup = BeautifulSoup(urllib.request.urlopen(url), 'html.parser')
        if len(soup.find_all('meta', content=True)) > 2:
            return -1
        else:
            return 1
    except:
        return -1

def on_mouseover(url):
    try:
        soup = BeautifulSoup(urllib.request.urlopen(url), 'html.parser')
        if soup.find('body').get('onmouseover'):
            return -1
        else:
            return 1
    except:
        return -1

def RightClick(url):
    try:
        soup = BeautifulSoup(urllib.request.urlopen(url), 'html.parser')
        if 'contextmenu' in soup.find('body').attrs:
            return -1
        else:
            return 1
    except:
        return -1

def popUpWidnow(url):
    try:
        soup = BeautifulSoup(urllib.request.urlopen(url), 'html.parser')
        if 'popup' in soup.find('script').attrs:
            return -1
        else:
            return 1
    except:
        return -1

def Iframe(url):
    try:
        soup = BeautifulSoup(urllib.request.urlopen(url), 'html.parser')
        if 'frameborder' in soup.find('iframe').attrs:
            return -1
        else:
            return 1
    except:
        return -1

def age_of_domain(url):
    try:
        w = whois.whois(url)
        creation_date = w.creation_date
        today = date.today()
        age = today.year - creation_date.year
        if age >= 6:
            return 1
        else:
            return -1
    except:
        return -1

def DNSRecord(url):
    try:
        domain = whois.whois(url)
        if domain:
            return 1
        else:
            return -1
    except:
        return -1

def web_traffic(url):
    try:
        xml = urllib.request.urlopen(
            'http://data.alexa.com/data?cli=10&dat=s&url=' + url).read()
        soup = BeautifulSoup(xml, 'xml')
        pop = soup.find('REACH')
        rank = int(pop['RANK'])
        if rank < 100000:
            return 1
        else:
            return 0
    except:
        return -1

def Page_Rank(url):
    try:
        xml = urllib.request.urlopen(
            'http://data.alexa.com/data?cli=10&dat=s&url=' + url).read()
        soup = BeautifulSoup(xml, 'xml')
        pop = soup.find('REACH')
        rank = int(pop['RANK'])
        if rank < 100000:
            return 1
        else:
            return 0
    except:
        return -1

def Google_Index(url):
    try:
        google = 'https://www.google.com/search?q=site:' + url
        soup = BeautifulSoup(urllib.request.urlopen(google), 'html.parser')
        if soup.find('a'):
            return 1
        else:
            return -1
    except:
        return -1

def Links_pointing_to_page(url):
    try:
        xml = urllib.request.urlopen(
            'http://data.alexa.com/data?cli=10&dat=s&url=' + url).read()
        soup = BeautifulSoup(xml, 'xml')
        pop = soup.find('LINKSIN')
        return int(pop['NUM'])
    except:
        return -1

def Statistical_report(url):
    try:
        xml = urllib.request.urlopen(
            'http://data.alexa.com/data?cli=10&dat=s&url=' + url).read()
        soup = BeautifulSoup(xml, 'xml')
        pop = soup.find('REACH')
        rank = int(pop['RANK'])
        if rank < 100000:
            return 1
        else:
            return 0
    except:
        return -1

def main(url):
    # Extract features
    features = [
        having_IP_Address(url),
        URL_Length(url),
        Shortining_Service(url),
        having_At_Symbol(url),
        double_slash_redirecting(url),
        Prefix_Suffix(url),
        having_Sub_Domain(url),
        SSLfinal_State(url),
        Domain_registeration(url),
        Favicon(url),
        port(url),
        HTTPS_token(url),
        Request_URL(url),
        URL_of_Anchor(url),
        Links_in_tags(url),
        SFH(url),
        Submitting_to_email(url),
        Abnormal_URL(url),
        Redirect(url),
        on_mouseover(url),
        RightClick(url),
        popUpWidnow(url),
        Iframe(url),
        age_of_domain(url),
        DNSRecord(url),
        web_traffic(url),
        Page_Rank(url),
        Google_Index(url),
        Links_pointing_to_page(url),
        Statistical_report(url),
    ]

    # Ensure the length of features is as expected
    assert len(features) == 30, f"Expected 30 features, got {len(features)}"
    
    return features
