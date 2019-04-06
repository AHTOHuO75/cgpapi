#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import sys
import socket
from pprint import pprint


class Cli:

	CLI_CODE={
		'OK': '200',
		'OK_INLINE': '201',
		'PASSWORD': '300',
		'UNKNOW_USER': '500',
		'GEN_ERR': '501',
		'STRANGE': '10000'
	}

	connection_parms = {
		'user': '',
		'password': '',
		'host': 'localhost',
		'port': 106,
		'ssl_transport': False,
		'secure_login': True,
		'webuser_login': False,
		'timeout': 60 * 5 - 5
	}

	def __init__(self, connection_parms):
		try:
			self.connection_parms['user'] = connection_parms['user']
		except KeyError:
			print("User is not defined")
			exit(1)
		try:
			self.connection_parms['password'] = connection_parms['password']
		except KeyError:
			print("Password is not defined")
			exit(1)
		self.connection_parms.update(connection_parms)
		try:
			self.sock = socket.socket()
		except socket.error:
			print('Failed to create socket')
			sys.exit()
		self.sock.settimeout(self.connection_parms['timeout'])
		self.sock.connect((self.connection_parms['host'], self.connection_parms['port']))
		response = self.sock.recv(1024)
		pprint(response)
		if self.connection_parms['ssl_transport']:
			pass
		else:
			pass
		if self.connection_parms['secure_login']:
			pass
		elif self.connection_parms['webuser_login']:
			pass
		else:
			pass
			print self.send2cli("USER " + self.connection_parms['user'])
			print self.send2cli("PASS " + self.connection_parms['password'])
	def __del__(self):
		self.sock.close()

	def send2cli(self, command):
		try:
			self.sock.sendall(bytes(command + "\r\n"))
		except socket.error:
			print("send2cli <"+command+"> failed")
			sys.exit()
		return self.sock.recv(1024)
