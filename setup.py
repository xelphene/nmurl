#!/usr/bin/env python

from distutils.core import setup
import sys

sys.path = ['.'] + sys.path
import nmurl.__init__
version = nmurl.__init__.__version__

setup(
	name='nmurl',
	version=version,
	description='nmine searches files for substrings that appear to be valid DNS names. It resolves them and outputs the result if the address it resolves to is of interest.',
	author='Steve Benson / Hurricane Labs',
	author_email='steve@hurricanelabs.com',
	license='GPLv3',
	url='http://www.hurricanelabs.com',
	packages=['nmurl/'],
	scripts=['scripts/nmurl']
)
