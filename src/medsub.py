import re
import sys
import argparse
import requests
from bs4 import BeautifulSoup
from argparse import HelpFormatter, ArgumentParser

VERSION = '0.0.2'

WARNING = '\033[93m'
RESET_ALL = '\033[0m'

found_subdomains = []

class CapitalizedHelpFormatter(HelpFormatter):
	def add_usage(self, usage, actions, groups, prefix=None):
		if not prefix:
			prefix = 'Usage: '

		return super().add_usage(usage, actions, groups, prefix)

def parse_arguments():
	parser = ArgumentParser(add_help=False, formatter_class=CapitalizedHelpFormatter)

	parser._optionals.title = 'Options'

	parser.add_argument('-h', action='help', help=argparse.SUPPRESS)

	parser.add_argument('-v', action='version', version=f'Medsub {VERSION}', help='Show version')

	parser.add_argument('-d', dest='domain', help='Target domain', required=True)

	parser.add_argument('-o', dest='output', help='Save the results in a file')

	return parser.parse_args()

class AnubisDB:
	name = 'AnubisDB'

	def search(self, domain):
		url = f'https://anubisdb.com/anubis/subdomains/{domain}'

		response = requests.get(url)

		subdomains = response.json()

		for found_subdomain in subdomains:
			if found_subdomain.endswith(domain) and found_subdomain not in found_subdomains:
				found_subdomains.append(found_subdomain)

class CertificateDetails:
	name = 'Certificate details'

	def search(self, domain):
		url = f'https://certificatedetails.com/{domain}'

		response = requests.get(url)

		body = response.text

		soup = BeautifulSoup(body, 'html.parser')

		tags = soup.find_all('div', class_='columns truncate text-center')

		pattern = f'^[0-9a-z.-]+.*{domain}$'

		for tag in tags:
			inner_html = tag.decode_contents()

			subdomains = inner_html.split('<br/>')

			for found_subdomain in subdomains:
				found_subdomain = found_subdomain.strip()

				if re.fullmatch(pattern, found_subdomain) and found_subdomain not in found_subdomains:
					found_subdomains.append(found_subdomain)

class CertificateSearch:
	name = 'Certificate Search'

	def search(self, domain):
		url = f'https://crt.sh/?q={domain}&exclude=expired&output=json'

		response = requests.get(url)

		certificates = response.json()

		pattern = f'^[0-9a-z.-]+.*{domain}$'

		for certificate in certificates:
			common_name = certificate['common_name']

			if re.fullmatch(pattern, common_name) and common_name not in found_subdomains:
				found_subdomains.append(common_name)

			name_value = certificate['name_value']

			subdomains = name_value.splitlines()

			for subdomain in subdomains:
				if re.fullmatch(pattern, subdomain) and subdomain not in found_subdomains:
					found_subdomains.append(subdomain)

class HackerTarget:
	name = 'Hacker Target'

	def search(self, domain):
		url = f'https://api.hackertarget.com/hostsearch/?q={domain}'

		response = requests.get(url)

		body = response.text

		lines = body.splitlines()

		pattern = f'^[0-9a-z.-]+.*{domain}$'

		for line in lines:
			found_subdomain = line.split(',')[0]

			if re.fullmatch(pattern, found_subdomain) and found_subdomain not in found_subdomains:
				found_subdomains.append(found_subdomain)

class HudsonRock:
	name = 'Hudson Rock'

	def search(self, domain):
		url = f'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain?domain={domain}'

		response = requests.get(url)

		data = response.json()

		clients_urls = data['data']['clients_urls']

		employees_urls = data['data']['employees_urls']

		records = clients_urls + employees_urls

		for record in records:
			compromised_url = record['url']

			found_subdomain = compromised_url.split('/')[2]

			if '•' not in found_subdomain and found_subdomain not in found_subdomains:
				found_subdomains.append(found_subdomain)

class RapidDNS:
	name = 'RapidDNS'

	def search(self, domain):
		page_number = 1

		max_page = 1

		while page_number < max_page + 1:
			url = f'https://rapiddns.io/s/{domain}?page={page_number}'

			response = requests.get(url)

			body = response.text

			if page_number == 1:
				matches = re.findall('\\/s\\/google\\.com\\?page=[0-9]+', body)

				max_page = int(matches[-2].split('=')[1])

			soup = BeautifulSoup(body, 'html.parser')

			tags = soup.find_all('td')

			for tag in tags:
				found_subdomain = tag.text

				if found_subdomain.endswith(domain) and found_subdomain not in found_subdomains:
					found_subdomains.append(found_subdomain)

			page_number += 1

def save_results(filename):
	file = open(filename, 'w')

	file.write('\n'.join(found_subdomains))

	file.close()

def main():
	args = parse_arguments()

	sources = [
		AnubisDB(),
		CertificateDetails(),
		CertificateSearch(),
		HackerTarget(),
		HudsonRock(),
		RapidDNS()
	]

	for source in sources:
		try:
			source.search(args.domain)
		except:
			print(f'{WARNING}Couldn\'t search for subdomains on {source.name}.{RESET_ALL}', file=sys.stderr)

	found_subdomains.sort()

	for found_subdomain in found_subdomains:
		print(found_subdomain)

	if args.output:
		try:
			save_results(args.output)
		except:
			print(f'{WARNING}Couldn\'t save the results in the file.{RESET_ALL}', file=sys.stderr)

try:
	main()
except KeyboardInterrupt:
	pass