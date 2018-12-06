#!/usr/bin/python3

import json
from haralyzer import HarParser, HarPage
from haralyzer.compat import iteritems


RESPONSE_HEADERS = ['Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials',
'Access-Control-Expose-Headers', 'Access-Control-Max-Age',
'Access-Control-Allow-Methods', 'Access-Control-Allow-Headers','Accept-Patch','Accept-Ranges','Age','Allow',
'Alt-Svc','Cache-Control','Connection','Content-Disposition','Content-Encoding','Content-Language','Content-Length',
'Content-Location','Content-MD5','Content-Range','Content-Type','Date','Delta-Base','ETag','Expires',
'IM','Last-Modified','Link','Location','P3P','Pragma','Proxy-Authenticate','Public-Key-Pins','Retry-After',
'Server','Set-Cookie','Strict-Transport-Security','Trailer','Transfer-Encoding',
'Tk','Upgrade','Vary','Via','Warning','WWW-Authenticate','X-Frame-Options']


REQUEST_HEADERS = ['A-IM','Accept','Accept-Charset','Accept-Datetime','Accept-Encoding',
'Accept-Language','Access-Control-Request-Method','Access-Control-Request-Headers',
'Authorization','Cache-Control','Connection','Content-Length',
'Content-MD5','Content-Type','Cookie','Date',
'Expect','Forwarded','From','Host','HTTP2-Settings',
'If-Match','If-Modified-Since''If-None-Match','If-Range','If-Unmodified-Since','Max-Forwards',
'Origin[8]','Pragma','Proxy-Authorization','Range','Referer','TE','Upgrade','User-Agent','Via','Warning']


print("Non-standard information in requests are:")
with open('arc.har','r') as f:
	data = HarParser(json.loads(f.read()))


	for page in data.pages:
		print(' ')
		print(' ')
		print(page)
		for entry in page.entries:
			tab = entry['request']['headers']
			for a in tab:
				if a['name'] not in REQUEST_HEADERS:
					print(a)
	print(' ')
	print(' ')
	print(' ')
	print("Non-standard informations for response are:")
	for page in data.pages:
		print(' ')
		print(' ')
		print(page)
		for entry in page.entries:
			tab = entry['response']['headers']
			for a in tab:
				if a['name'] not in RESPONSE_HEADERS:
					print(a)
