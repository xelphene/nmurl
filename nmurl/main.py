
import optparse
import sys

import nmurl.parsedns
import nmurl.parsenmap

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
		usage="%prog [-n <lookups>] <nmap xml> [<nmap xml> ...]",
		version="%prog v1.0"
	)
	parser.remove_option('--version')

	parser.add_option('-n', '--names',
		action='append',
		dest='names',
		type='str',
		default=[],
		help='Load DNS lookups (in BIND zone format) from this file')

	parser.add_option('-v', '--version',
		action='version',
		help='Display version number and exit')
		
	parser.add_option('-d', '--debug',
		action='store_true',
		default=False,
		help='Turn on debug logging output')

	(opts,args) = parser.parse_args(argv)

	nmapFiles = args[1:]
	nameFiles = opts.names
	
	if len(nmapFiles)==0:
		raise NoNmapFilesError()

	return (nmapFiles, nameFiles)
	
def mainInner():
	(nmapFiles, nameFiles) = parseArgs()
	urlList = URLList()
	
	print 'nmapFiles:',repr(nmapFiles)
	print 'nameFiles:',repr(nameFiles)
	
	rrsl = nmurl.parsedns.RRSetList()

	for nameFile in nameFiles:
		try:
			f = open(nameFile)
		except Exception, e:
			raise NameFileError(nameFile, e)
		else:
			nmurl.parsedns.parseFile(f, rrsl)

	for nmapFile in nmapFiles:
		print '*',nmapFile
		f = open(nmapFile)
		p = nmurl.parsenmap.FileParser(
			onPortOpen = urlList.portOpen,
			onServiceProbed = urlList.serviceProbed
		)
		p.parse(f)

def guessScheme(portNum):

	# TODO
	
	if portNum in (443, 8443):
		return 'https'
	elif '443' in str(portNum):
		return 'https'
		

class URLList:
	def __init__(self):
		pass
	
	def portOpen(self, parserInfo):
		# TODO
		pass
		
	def serviceProbed(self, parserInfo):
		#print 'serviceProbed:',parserInfo
		if parserInfo.get('name')=='http':
			if parserInfo.get('tunnel')=='ssl':
				if parserInfo['port']==443:
					url = 'https://%s/' % parserInfo['address']
				else:
					url = 'https://%s:%s/' % (parserInfo['address'], parserInfo['port'])
			else:
				if parserInfo['port']==80:
					url = 'http://%s/' % parserInfo['address']
				else:
					url = 'http://%s:%s/' % (parserInfo['address'], parserInfo['port'])
			print 'URL',url
				
	
def main():
	try:
		mainInner()
	except NameFileError, n:
		print n
	except NoNmapFilesError, n:
		print n

	