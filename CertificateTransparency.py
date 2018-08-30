import requests
import json
import time
import base64
import ctl_parser_structures
from pyasn1.codec.der import decoder
from pyasn1_modules import pem, rfc2459
from OpenSSL import crypto

class CertTransLog():
	def __init__(self):
		self.logs_servers=[
			'https://ct.cloudflare.com/logs/nimbus2018'
		]
		self._init_count_entrys()

	def _init_count_entrys(self):
		self.last_entries = [self._find_last_entry_id() for self.sv in self.logs_servers]

	def _find_last_entry_id(self):
		flag = True
		tree_size = requests.get(self.sv+'/ct/v1/get-sth').json()['tree_size']
		while flag:
			res = requests.get(self.sv+'/ct/v1/get-entries', params={'start': tree_size, 'end': tree_size+1000}).json()
			if res['entries'] is None:
				res = requests.get(self.sv+'/ct/v1/get-entries', params={'start': tree_size-1, 'end': tree_size-1}).json()
			if len(res['entries']) < 1000:
				tree_size += res['entries'].index(res['entries'][-1])
				res = requests.get(self.sv+'/ct/v1/get-entries', params={'start': tree_size-1, 'end': tree_size+1000}).json()
				return {
						'server': self.sv,
						'last_entry_id': tree_size,
						'entries': res['entries']
				 	}
			tree_size += 1000

	def _get_domains_from_server(self):
		domains = []
		for cert in self.entry['entries']:
			leaf_cert = ctl_parser_structures.MerkleTreeHeader.parse(base64.b64decode(cert['leaf_input']))
			if leaf_cert.LogEntryType == "X509LogEntryType":
				cert_data_string = ctl_parser_structures.Certificate.parse(leaf_cert.Entry).CertData
				chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data_string)]
			else:
				extra_data = ctl_parser_structures.PreCertEntry.parse(base64.b64decode(cert['extra_data']))
				chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData)]
			if len(chain)>0: 
				domain = chain[0].get_subject().CN
				if domain != None and not '*' in domain: domains.append(domain)
		return domains

	def _get_more_domains(self):
		if self.entry['entries'] != None: self.entry['last_entry_id'] += len(self.entry['entries'])
		res = requests.get(
				self.entry['server'] + '/ct/v1/get-entries', 
				params={'start': self.entry['last_entry_id'], 'end': self.entry['last_entry_id']+1000}
			).json()
		self.entry['entries'] = res['entries']
		self.last_entries[self.index] = self.entry

	def get_fresh_domains(self):
		while True:
			for self.index,self.entry in enumerate(self.last_entries):
				if self.entry['entries'] != None: yield self._get_domains_from_server()
				self._get_more_domains()
			print('[*] - Sleep 30 seconds')
			time.sleep(30)


