
import datetime
import xml.parsers.expat
import logging
import re
import copy

class ParseError(Exception):
	def __init__(self, reason, path):
		self.reason = reason
		self.path = path
	
	def __str__(self):
		return 'Error parsing nmap XML file %s: %s' % (self.path, self.reason)
	

class FileParser:
	def __init__(self):
		self.log = logging.getLogger('nmurl.parse')
		
		self._run_startts = None
		self._path = []
		self.cur_host_ipv4addr = None
		self.cur_port_num = None
		self.cur_port_proto = None
		self.cur_port_state = None
		self.cur_port_service = None
		self.cur_host_specedports = set()
		self.cur_host_extra_state = None # state of all ports not explicitly specified in results
		self.cur_host_state = None # up or down
		self._scanned_ports = {}
		self._scan_types = {}

	def parse(self, f):
		self._file = f
		self.parseInner()
		
	def current_path(self):
		return [pe['name'] for pe in self._path]

	def current_path_str(self):
		return '.'.join(self.current_path())

	def parseInner(self):
		parser = xml.parsers.expat.ParserCreate()
		parser.StartElementHandler = self.p_start
		parser.EndElementHandler = self.p_end
		parser.CharacterDataHandler = self.p_data
		
		chunk = self._file.read(1024)
		while chunk:
			try:
				parser.Parse(chunk)
			except xml.parsers.expat.ExpatError, e:
				raise ParseError(
					reason=str(e),
					context=chunk,
					path=self._file.name,
					format='nmap_xml')
			#if len(self._obs_cache)>0:
			#	for obs in self._obs_cache:
			#		yield obs
			#self._obs_cache = []
			chunk = self._file.read(1024)
		
		try:
			parser.Parse('',True) # tell the parser that was it
		except xml.parsers.expat.ExpatError, e:
			raise ParseError(
				reason=str(e),
				path=self._file.name)
		

	def p_start(self, name, attrs):
		if self.current_path_str()=='':
			if name!='nmaprun':
				raise ParseError(
					reason='open tag is not nmaprun',
					path=self._file.name
				)
	
		# turn attrs into plain strings instead of unicode
		attrs = dict( [(str(k), str(v)) for (k,v) in attrs.items()] )
		self._path.append( {
			'name': name,
			'attrs': attrs } )

		if self.current_path_str()=='nmaprun':
			self._run_startts = int(attrs['start'])

		if self.current_path_str()=='nmaprun.runstats.finished':
			self._run_endts = int(attrs['time'])
			#self._e.set_end( int(attrs['time']) )
		
		if self.current_path_str()=='nmaprun.host.status':
			self.cur_host_state = attrs['state']
		
		if self.current_path_str()=='nmaprun.host.address':
			if attrs['addrtype']=='ipv4':
				self.cur_host_ipv4addr = attrs['addr']
		
		if self.current_path_str()=='nmaprun.host.ports.port':
			self.cur_port_proto = attrs['protocol']
			self.cur_port_num = int(attrs['portid'])
			self.cur_port_scripts = []
		
		if self.current_path_str()=='nmaprun.host.ports.port.state':
			self.cur_port_state = attrs['state']
		
		if self.current_path_str()=='nmaprun.scaninfo':
			self._scanned_ports[ str(attrs['protocol']) ] = parse_scaninfo_services(str(attrs['services']))
			self._scan_types[ attrs['protocol'] ] = str(attrs['type'])
	
		if self.current_path_str()=='nmaprun.host.ports.extraports':
			self.cur_host_extra_state = attrs['state']
		
		if self.current_path_str()=='nmaprun.host.ports.port.service':
			if attrs.has_key('product') and attrs.has_key('version'):
				#self.cur_port_service = ( attrs['product'], attrs['version'] )
				self.cur_port_service = copy.copy(attrs)
		
		if self.current_path_str()=='nmaprun.host.ports.port.script':
			self.cur_port_scripts.append({
				'id': attrs.get('id'),
				'output': attrs.get('output')
			})
	
	def report_port_state(self, mode, address, proto, port, state):
		#self._report.state(mode, address, proto, port, state)
		return
	
	def p_end(self, name):
		assert self._path[-1]['name']==name
		
		if self.current_path_str() == 'nmaprun.host.ports.port':
			self.cur_host_specedports.add( (self.cur_port_proto, self.cur_port_num) )
			if self.cur_port_state=='open':
				if self.cur_port_state == 'open' and self.cur_port_num in (80,443):
					d = {
						'address': self.cur_host_ipv4addr,
						'proto': self.cur_port_proto,
						'port': self.cur_port_num
					}
					print 'PORT:',d

				if self.cur_port_service != None:
					d = self.cur_port_service
					d['path'] = self._file.name
					d['address'] = self.cur_host_ipv4addr
					d['proto'] = self.cur_port_proto
					d['port'] = self.cur_port_num
					print 'SERVICE:',d
					
			self.cur_port_proto = None
			self.cur_port_num = None
			self.cur_port_state = None
			self.cur_port_service = None
				
			
			# reset host things back to defaults
			self.cur_host_state = None
			self.cur_host_ipv4addr = None
			self.cur_host_specedports = set()
			self.cur_host_extra_state = None
			
		
		# KEEP AT END
		self._path = self._path[:-1]
	
	def p_data(self, data):
		pass
	
def parse_scaninfo_services(services):
	services_set = set()
	services_ranges = []
	services = str(services) # cast from unicode
	service_re = re.compile('^([0-9]{1,5})$')
	multiservice_re = re.compile('^([0-9]{1,5})-([0-9]{1,5})$')
	for part in services.split(','):
		mg = service_re.match(part)
		if mg:
			services_set.add( int(mg.group(1)) )
		else:
			mg = multiservice_re.match(part)
			if mg:
				for p in range( int(mg.group(1)), int(mg.group(2))+1 ):
					services_set.add(p)
			else:
				raise ValueError('unparseable services, unparseable part %s' % repr(part))
	return services_set
		
