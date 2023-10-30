#!/usr/bin/env python

import re
import sys


class ParseError:
	def setDefaults(self):
		if self.format==None:
			self.format='dig'

class RRSet(object):
	
	"""an RRSet contains one or more resource records of the same name,
	type and class (and possibly TTL, not sure what to do with that yet."""

	def __init__(self, name=None, rclass=None, rtype=None, ttl=0, data=None):
		self.name = name
		self.rclass = rclass
		self.rtype = rtype
		self.ttl = ttl
		if data==None:
			self.data = []
		else:
			self.data = data
	
	def addData(self, data):
		if data not in self.data:
			self.data.append(data)
	
	def __iter__(self):
		for datum in self.data:
			yield RR(
				name=self.name,
				rclass=self.rclass,
				rtype=self.rtype,
				ttl=self.ttl,
				data=datum)

	def __str__(self):
		return 'RRSet: %s %s %s' % (self.name, self.rclass, self.rtype)

class RRSetList(object):

	"""builds a list of distinct RRSets from RRs."""
	
	def __init__(self):
		self.rrsets = {}
		self._resolutionsCache = None

	def __iter__(self):
		for rrset in list(self.rrsets.values()):
			yield rrset
	
	def addRR(self, rr):
		self._resolutionsCache = None
		key = (rr.name,rr.rclass,rr.rtype)
		if key not in self.rrsets:
			self.rrsets[key] = RRSet(
				name=rr.name, 
				rtype=rr.rtype,
				rclass=rr.rclass )
		self.rrsets[key].ttl = rr.ttl # TODO: not sure about this
		self.rrsets[key].addData(rr.data)

	def names(self):
		"""return all domain names used anywhere in this query"""
		s = set()
		for rrset in self:
			n = rrset.name
			if n.endswith('.'): n=n[:-1]
			s.add(rrset.name)
			if rrset.rtype=='CNAME':
				for datum in rrset.data:
					if datum.endswith('.'):
						datum = datum[:-1]
					s.add(datum)
		return s

	def buildResolutions(self): 

		"""return a dictionary with IP addresses for keys and arrays of
		hostnames that resolve to it (either via n A or CNAME record) as the
		corresponding values."""
		
		r={
			'reverse': {},
			'forward': {}
		}
		
		for rrset in self:
			if rrset.rtype!='A':
				continue
			if rrset.name not in r['forward']:
				r['forward'][rrset.name] = set()
			for address in rrset.data:
				r['forward'][rrset.name].add(address)
				if address not in r['reverse']:
					r['reverse'][address] = set()
				r['reverse'][address].add(rrset.name)

		for rrset in self:
			if rrset.rtype!='CNAME':
				continue
			for datum in rrset.data:
				# datum is the CNAME TARGET
				if datum.endswith('.'):
					datum = datum[:-1]
				if datum in r['forward']:
					addrs = r['forward'][datum]
					r['forward'][rrset.name] = addrs
					for addr in addrs:
						r['reverse'][addr].add(rrset.name)

		return r

	def getResolutions(self):
		if self._resolutionsCache:
			return self._resolutionsCache
		else:
			self._resolutionsCache = self.buildResolutions()
			return self._resolutionsCache
		
	def namesForAddress(self, addr):
		if addr in self.getResolutions()['reverse']:
			return self.getResolutions()['reverse'][addr]
		else:
			return set([])
		
	def dump(self):
		print('--- dns query')
		for rrset in self:
			print(rrset)
			for rr in rrset:
				print('   ',rr.simpleFormat())
		print(' res:',self.getResolutions())

class RR(object):
	def __init__(self, name=None, rclass=None, rtype=None, ttl=0, data=None):
		self.name = name
		self.rclass = rclass
		self.rtype = rtype
		self.ttl = ttl
		self.data = data
	
	def simpleFormat(self):
		if len(self.data)>30:
			data = self.data[0:30]+'...'
		else:
			data = self.data
		return '%-30s %2s  %-4s %s' % (
			self.name, self.rclass, self.rtype, data)
	
	def fullFormat(self):
		return '%-30s %-10d %-2s %-4s %s' % (
			self.name, self.ttl, self.rclass, self.rtype, self.data)
	
	def __str__(self):
		return 'Fact: %s' % self.simpleFormat()
		#return 'Fact: %s %d %s %s %s' % (
		#	self.name, self.ttl, self.rclass, self.rtype, self.data)
		
class RRParseError(Exception):
	def __init__(self, s, reason):
		self.string = s
		self.reason = reason
	
	def __str__(self):
		return 'failed to parse %s as fact: %s' % (
			repr(self.string), self.reason )

class RRParser(object):
	re_rr = re.compile('^(\S+)\.\s+([0-9]+)\s+([A-Z]+)\s+([A-Z]+)\s+(.*)$')

	@classmethod
	def parseString(cls, s):
		mg = cls.re_rr.match(s)
		if mg==None:
			raise RRParseError(s,'invalid format')
		return RR(
			name = mg.group(1),
			rclass = mg.group(3),
			rtype = mg.group(4),
			ttl = int(mg.group(2)),
			data = mg.group(5)
		)

def parseFile(f, rrsl=None):
	lineno=0
	if rrsl==None:
		rrsl = RRSetList()
	
	for line in f:
		
		lineno+=1
		try:
			rr = RRParser.parseString(line)
			rrsl.addRR(rr)			
		except RRParseError as rpe:
			#print '<failed>',rpe
			pass
	
	return rrsl
		