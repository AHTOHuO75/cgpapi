#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import socket

class cli:

	def __init__(self, host_ = 'localhost', port_ = 106, ssl_transport = 1, secure_login = 1, webuser_login = 0, timeout = 60*5-5):
		self.sock = socket.socket()
		self.sock.settimeout(timeout)
		self.sock.connect((host_,port_))

	def __del__(self):
		self.sock.close()



