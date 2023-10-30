
import optparse
import sys
import logging

import nmurl.parsedns
import nmurl.parsenmap

import ipcidrtree

class NameFileError(Exception):
	def __init__(self, nameFile, exc):
		self.nameFile=nameFile
		self.exc=exc
	def __str__(self):
		return 'Error opening DNS lookups file %s: %s' % (self.nameFile, self.exc)

class NoNmapFilesError(Exception):
	def __str__(self):
		return 'No Nmap XML files specified as arguments.'

def parseArgs(argv=sys.argv):
	parser = optparse.OptionParser(
		usage="%prog [-n <dns lookups file>] <nmap xml file> [<nmap xml file> ...]",
		version="%prog v1.0"
	)
	parser.remove_option('--version')

	parser.add_option('-n', '--names',
		action='append',
		dest='nameFiles',
		type='str',
		default=[],
		help='Load DNS lookups (in BIND zone format) from this file. May be specified multiple times.')

	parser.add_option('-S', '--httpsPort',
		action='append',
		dest='forceHttpsPorts',
		type='int',
		default=[],
		help="If this port is open, assume it is HTTPS regardless of nmap's stated service name"
	)
	parser.add_option('-H', '--httpPort',
		action='append',
		dest='forceHttpPorts',
		type='int',
		default=[],
		help="If this port is open, assume it is HTTP regardless of nmap's stated service name"
	)

	parser.add_option('-v', '--version',
		action='version',
		help='Display version number and exit.')
		
	parser.add_option('-d', '--debug',
		action='store_true',
		default=False,
		help='Turn on debug logging output.')

	(opts,args) = parser.parse_args(argv)

	nmapFiles = args[1:]
	
	if len(nmapFiles)==0:
		raise NoNmapFilesError()

	opts.nmapFiles = nmapFiles

	return opts
	
def genurl(host, port, scheme):
	if scheme=='https' and port==443:
		return 'https://%s' % host
	elif scheme=='http' and port==80:
		return 'http://%s' % host
	else:
		return '%s://%s:%s' % (scheme, host, port)

def initLogging(debug):
	log = logging.getLogger('nmurl')
	handler = logging.StreamHandler(sys.stderr)
	if debug:
		formatter = logging.Formatter('%(asctime)s %(name)s: %(message)s','%X')
	else:
		formatter = logging.Formatter('%(name)s: %(message)s')
	handler.setFormatter(formatter)
	log.addHandler(handler)
	if debug:
		log.setLevel(logging.DEBUG)
	else:
		log.setLevel(logging.ERROR)

def writeResults(urlsByAddrAndPort):
	log = logging.getLogger('nmurl')
	addrs = list(urlsByAddrAndPort.keys())
	addrs = [ipcidrtree.Prefix(a) for a in addrs]
	addrs.sort()
	for addr in addrs:
		addr_str = str(addr.address()) # normally an ipcidrtree.Prefix object
		log.debug('writing results for %s' % addr)
		ports = list(urlsByAddrAndPort[addr_str].keys())
		ports.sort()
		for port in ports:
			log.debug('  port %s' % port)
			urls = urlsByAddrAndPort[addr_str][port]
			urls = list(urls) # is a set	
			urls.sort()
			for url in urls:
				print(url)
	
def mainInner():
	opts = parseArgs()
	initLogging(opts.debug)
	log = logging.getLogger('nmurl')
	
	log.debug('nmapFiles: %s' % repr(opts.nmapFiles) )
	log.debug('nameFiles: %s' % repr(opts.nameFiles) )
	log.debug('forceHttpPorts: %s' % repr(opts.forceHttpPorts) )
	log.debug('forceHttpsPorts: %s' % repr(opts.forceHttpsPorts) )
	
	# DNS lookups are stored here
	rrsl = nmurl.parsedns.RRSetList()

	for nameFile in opts.nameFiles:
		try:
			f = open(nameFile)
		except Exception as e:
			raise NameFileError(nameFile, e)
		else:
			nmurl.parsedns.parseFile(f, rrsl)

	urlsByAddrAndPort = {}
	
	def nmapHandler(d):
		log.debug('parser result: %s' % repr(d))
		port = d['port']
		addr = d['address']
		if d['service']['name']=='http' and d['service'].get('tunnel') == 'ssl':
			svc = 'https'
		else:
			svc = d['service']['name']

		if port in opts.forceHttpPorts:
			url = genurl(addr, port, 'http')
			log.debug('FORCED HTTP')
			scheme = 'http'
		elif port in opts.forceHttpsPorts:
			url = genurl(addr, port, 'https')
			log.debug('FORCED HTTPS')
			scheme = 'https'
		else:
			scheme = svc
		
		if addr not in urlsByAddrAndPort:
			urlsByAddrAndPort[addr] = {}
		if port not in urlsByAddrAndPort[addr]:
			urlsByAddrAndPort[addr][port] = set()
		
		log.debug('URL: %s' % genurl(addr, port, scheme))
		urlsByAddrAndPort[addr][port].add( genurl(addr, port, scheme) )
		for name in rrsl.namesForAddress(addr):
			log.debug('URL: %s' % genurl(name, port, scheme))
			urlsByAddrAndPort[addr][port].add( genurl(name, port, scheme) )
		
	for nmapFile in opts.nmapFiles:
		log.debug('START %s' % nmapFile)
		f = open(nmapFile)
		parser = nmurl.parsenmap.FileParser()
		parser.addInterestingService('http')
		parser.addInterestingService('https')
		for port in opts.forceHttpPorts:
			parser.addInterestingPort(port)
		for port in opts.forceHttpsPorts:
			parser.addInterestingPort(port)
		parser.setInterestingPortCallback(nmapHandler)
		parser.setInterestingServiceCallback(nmapHandler)
		try:
			parser.parse(f)
		except nmurl.parsenmap.ParseError as pe:
			log.error('Error parsing %s: %s' % (nmapFile, pe))
		log.debug('END %s' % nmapFile)

	log.debug('end all parsing. writing results.')

	writeResults(urlsByAddrAndPort)
	
def main():
	try:
		mainInner()
	except NameFileError as n:
		print(n)
	except NoNmapFilesError as n:
		print(n)

	