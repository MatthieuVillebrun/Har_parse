#!/usr/bin/python3

import json
from haralyzer import HarParser, HarPage
from haralyzer.compat import iteritems


FIELDSs = ['Accept','Accept-Charset','Accept-Encoding','Accept-Language','Accept-Ranges',
'Access-Control-Allow-Credentials','Access-Control-Allow-Headers',
'Access-Control-Allow-Methods','Access-Control-Allow-Origin',
'Access-Control-Expose-Headers','Access-Control-Max-Age','Access-Control-Request-Headers',
'Access-Control-Request-Method','Age','Allow','Alt-Svc','Authorization',
'Cache-Control','Clear-Site-Data','Connection','Content-Disposition',
'Content-Encoding','Content-Language','Content-Length','Content-Location',
'Content-Range','Politique de sécurité de contenu','Content-Security-Policy-Report-Only',
'Content-Type','Cookie','Cookie2','DNT','Date','ETag','Early-Data','Expect',
'Expect-CT','Expires','Feature-Policy','Forwarded','From','Host','If-Match',
'If-Modified-Since','If-None-Match','If-Range','If-Unmodified-Since','Index',
'Keep-Alive','Large-Allocation','Last-Modified','Location','Origin','Pragma',
'Proxy-Authenticate','Proxy-Authorization','Public-Key-Pins',
'Public-Key-Pins-Report-Only','Range','Referer','Referrer-Policy',
'Retry-After','Sec-WebSocket-Accept','Serveur','Server-Timing',
'Set-Cookie','Set-Cookie2','SourceMap','HTTP Strict Transport Security',
'TE','Timing-Allow-Origin','Tk','Trailer','Transfer-Encoding',
'Upgrade-Insecure-Requests','User-Agent','Vary','Via',
'WWW-Authenticate','Warning','X-Content-Type-Options','X-DNS-Prefetch-Control',
'X-Forwarded-For','X-Forwarded-Host','X-Forwarded-Proto',
'X-Frame-Options','X-XSS-Protection','Accept-Ranges','Age'
'ETag','Location','Proxy-Authenticate','Retry-After','Server',
'Vary','WWW-Authenticate','Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials',
'Access-Control-Expose-Headers', 'Access-Control-Max-Age',
'Access-Control-Allow-Methods', 'Access-Control-Allow-Headers','Accept-Patch','Accept-Ranges','Age','Allow',
'Alt-Svc','Cache-Control','Connection','Content-Disposition','Content-Encoding','Content-Language','Content-Length',
'Content-Location','Content-MD5','Content-Range','Content-Type','Date','Delta-Base','ETag','Expires',
'IM','Last-Modified','Link','Location','P3P','Pragma','Proxy-Authenticate','Public-Key-Pins','Retry-After',
'Server','Set-Cookie','Strict-Transport-Security','Trailer','Transfer-Encoding',
'Tk','Upgrade','Vary','Via','Warning','WWW-Authenticate','X-Frame-Options','A-IM','Accept','Accept-Charset','Accept-Datetime','Accept-Encoding',
'Accept-Language','Access-Control-Request-Method','Access-Control-Request-Headers',
'Authorization','Cache-Control','Connection','Content-Length',
'Content-MD5','Content-Type','Cookie','Date',
'Expect','Forwarded','From','Host','HTTP2-Settings',
'If-Match','If-Modified-Since','If-None-Match','If-Range','If-Unmodified-Since','Max-Forwards',
'Origin','Pragma','Proxy-Authorization','Range','Referer','TE','Upgrade','User-Agent','Via','Warning']

FIELDS = []
for a in FIELDSs:
    FIELDS.append(a.lower())

#print("Non-standard information in requests are:")


with open('arc.har','r') as f:
    data = HarParser(json.loads(f.read()))

for page in data.pages:
    print(page)
    for entry in page.entries:
        toprint = ""
        reqHtab = entry['request']['headers']
        respHtab = entry['response']['headers']
        toprint = toprint + entry['request']['url'] +"\n" +  entry['request']['httpVersion'] + "\n"+ "Requests:\n"
        #print(entry['request']['url'])
        #print(entry['request']['httpVersion'])
        for aa in reqHtab:
            if aa['name'].lower() not in FIELDS:
                toprint = toprint + str(aa) +"\n"
        toprint = toprint + "\n" + "Responce:\n"
        for bb in respHtab:
            if bb['name'].lower() not in FIELDS:
                toprint = toprint + str(bb) +"\n"
        print(toprint)
"""
print(' ')
print(' ')
print(' ')
print("Non-standard informations for response are:")
for page in data.pages:
print(' ')
print(' ')
print(page)
for entry in page.entries:
print(' ')
taba = entry['response']['headers']
print(entry['response']['httpVersion'])
print(' ')
for ab in taba:
if ab['name'].lower() not in FIELDS:
print(ab)
"""
