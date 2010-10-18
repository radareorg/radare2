#!/usr/bin/python
#
# Python implementation of the radare remote protocol
#

##===================================================0
## server api
##===================================================0

from socket import *
from struct import *
import traceback
import sys

RAP_OPEN   = 1
RAP_READ   = 2
RAP_WRITE  = 3
RAP_SEEK   = 4
RAP_CLOSE  = 5
RAP_SYSTEM = 6
RAP_CMD    = 7
RAP_REPLY  = 0x80

# TODO: Add udp
# TODO: allow to init funptrs with a tuple
class RapServer():
	def __init__(self):
		self.offset = 0
		self.size = 0
		self.handle_eof = None
		self.handle_cmd_system = None
		self.handle_cmd_seek   = None
		self.handle_cmd_read   = None
		self.handle_cmd_write  = None
		self.handle_cmd_open   = None
		self.handle_cmd_close  = None

	def _handle_packet(self, c, key):
		ret = ""
		if key == RAP_OPEN:
			buffer = c.recv(2)
			(flags, length) = unpack(">BB", buffer)
			file = c.recv(length)
			if self.handle_cmd_open != None:
				fd = self.handle_cmd_open(file, flags)
			else: 	fd = 3434
			buf = pack(">Bi", key|RAP_REPLY, fd)
			c.send(buf)
		elif key == RAP_READ:
			buffer = c.recv(4)
			(length,) = unpack(">I", buffer)
			if self.handle_cmd_read != None:
				ret = str(self.handle_cmd_read(length))
				try:
					lon = len(ret)
				except:
					ret = ""
					lon = 0
			else:
				ret = ""
				lon = 0;
			buf = pack(">Bi", key|RAP_REPLY, lon)
			c.send(buf+ret)
		elif key == RAP_WRITE:
			buffer = c.recv(4)
			(length,) = unpack(">I", buffer)
			buffer = c.recv(length)
			# TODO: get buffer and length
			if self.handle_cmd_write != None:
				length = self.handle_cmd_write (buffer)
			buf = pack(">Bi", key|RAP_REPLY, length)
			c.send(buf)
		elif key == RAP_SEEK:
			buffer = c.recv(9)
			(type, off) = unpack(">BQ", buffer)
			if self.handle_cmd_seek != None:
				seek = self.handle_cmd_seek(off, type)
			else:
				if   type == 0: # SET
					seek = off;
				elif type == 1: # CUR
					seek = seek + off 
				elif type == 2: # END
					seek = self.size;
			self.offset = seek
			buf = pack(">BQ", key|RAP_REPLY, seek)
			c.send(buf)
		elif key == RAP_CLOSE:
			if self.handle_cmd_close != None:
				length = self.handle_cmd_close (fd)
		elif key == RAP_SYSTEM:
			buf = c.recv(4)
			(length,) = unpack(">i", buf)
			ret = c.recv(length)
			if self.handle_cmd_system != None:
				reply = self.handle_cmd_system(ret)
			else:	reply = ""
			buf = pack(">Bi", key|RAP_REPLY, len(str(reply)))
			c.send(buf+reply)
		else:
			print "Unknown command"
			c.close()

	def _handle_client(self, c):
		while True:
			try:
				buf = c.recv(1)
				if buf == "" and self.handle_eof is not None:
					self.handle_eof(c)
					break
				if len(buf) == 0:
					print "Connection closed\n"
					break
				self._handle_packet(c, ord(buf))
			except KeyboardInterrupt:
				break

	def listen_tcp(self, port):
		s = socket();
		s.bind(("0.0.0.0", port))
		s.listen(999)
		print "Listening at port %d"%port
		while True:
			(c, (addr,port)) = s.accept()
			print "New client %s:%d"%(addr,port)
			self._handle_client(c)


##===================================================0
## client api
##===================================================0

class RapClient():
	def __init__(self, host, port):
		self.connect_tcp(host, port)

	def connect_tcp(self, host, port):
		fd = socket();
		fd.connect((host, port))
		self.fd = fd

	def disconnect(self):
		self.fd.close()
		self.fd = None

	def open(self, file, flags):
		b = pack(">BBB", RAP_OPEN, flags, len(file))
		self.fd.send(b)
		self.fd.send(file)
		# response
		buf = self.fd.recv(5)
		(c,l) = unpack(">Bi", buf)
		if c != (RAP_REPLY|RAP_OPEN):
			print "rmt-open: Invalid response packet 0x%02x"%c
		return l

	def read(self, count):
		b = pack(">Bi", RAP_READ, count) #len(buf))
		self.fd.send(b)
		# response
		buf = self.fd.recv(5)
		(c,l) = unpack(">Bi", buf)
		buf = self.fd.recv(l)
		return buf

	# TODO: not tested
	def write(self, buf):
		#self.fd.send(buf)
		b = pack(">Bi", RAP_WRITE, len(buf))
		self.fd.send(b+buf)
		# response
		buf = self.fd.recv(5)
		(c,l) = unpack(">Bi", buf)
		if c != (RAP_REPLY|RAP_WRITE):
			print "rmt-write: Invalid response packet 0x%02x"%c

	def lseek(self, type, addr):
		# WTF BBQ?
		buf = pack(">BBQ", RAP_SEEK, type, addr)
		self.fd.send(buf)
		# read response
		buf = self.fd.recv(5) # XXX READ 5!?!?!? shouldnt be 9 ?!?!? WTF
		(c,l) = unpack(">Bi", buf)
		#print "Lseek : %d"%l
		return l

	def close(self, fd):
		buf = pack(">Bi", RAP_CLOSE, fd)
		self.fd.send(buf)
		# read response
		buf = self.fd.recv(5)
		(c,l) = unpack(">Bi", buf)
		if c != RAP_REPLY | RAP_CLOSE:
			print "rmt-close: Invalid response packet"

	def cmd(self, cmd):
		buf = pack(">Bi", RAP_CMD, len(str(cmd)))
		self.fd.send(buf + cmd)
		# read response
		buf = self.fd.recv(5)
		(c,l) = unpack(">Bi", buf)
		if c != RAP_CMD | RAP_REPLY:
			print "rmt-cmd: Invalid response packet"
			return ""
		buf = self.fd.recv(l)
		return buf

	def system(self, cmd):
		buf = pack(">Bi", RAP_SYSTEM, len(str(cmd)))
		self.fd.send(buf)
		self.fd.send(cmd)
		# read response
		buf = self.fd.recv(5)
		(c,l) = unpack(">Bi", buf)
		if c != RAP_SYSTEM | RAP_REPLY:
			print "rmt-system: Invalid response packet"
			return ""
		if l>0:
			buf = self.fd.recv(l)
		return buf
