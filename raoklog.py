# -*- coding: utf-8 -*-
import time,datetime
import os,sys
import logging
import logging.config

__vis_filter = """................................ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`abcdefghijklmnopqrstuvwxyz{|}~................................................................................................................................."""
def hexdump(buf, length=16):
    """Return a hexdump output string of the given buffer."""
    n = 0
    res = []
    while buf:
        line, buf = buf[:length], buf[length:]
        hexa = ' '.join(['%02x' % ord(x) for x in line])
        line = line.translate(__vis_filter)
        res.append('  %04d:  %-*s %s' % (n, length * 3, hexa, line))
        n += length
    return '\n'.join(res)



class raoklog:
	logger = None
	separator = ": "
	verbose = {}

	def __init__(self):
		self.configure()
		self.verbose['connections'] = False

	def configure(self):
		try:
			logging.config.fileConfig('etc/nlog.conf')
			self.logger = logging.getLogger("NLog")
			return True
		except Exception,e:
			print "LOGGER INIT FAILURE: " + str(e)
			return False

	def debug(self,msg,pfx=""):
		self.logger.debug(pfx + self.separator + msg)
	def info(self,msg,pfx=""):
		self.logger.info(pfx + self.separator + msg)
	def warning(self,msg,pfx=""):
		self.logger.warn(pfx + self.separator + msg)
	def error(self,msg,pfx=""):
		self.logger.error(pfx + self.separator + msg)
	def critical(self,msg,pfx=""):
		self.logger.critical(pfx + self.separator + msg)
	def hexdump(self,msg,pfx=""):
		self.logger.debug(pfx + self.separator + "\n" + hexdump(msg))

raoklog = raoklog()
	
		
