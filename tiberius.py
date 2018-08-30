from modules.CertificateTransparency import *
from modules.CMSCrawler import *
import time

def main():
	ct = CertTransLog()
	cms = CMS()

	for domains in ct.get_fresh_domains():
		for domain in domains:
			cms.process(domain)

if __name__ == "__main__": 
    main()
