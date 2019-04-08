#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import sys
import socket
import ssl
import re
import hashlib
from pprint import pprint


class Cli:
    CLI_CODE = {
        'OK': '200',
        'OK_INLINE': '201',
        'PASSWORD': '300',
        'UNKNOWN_USER': '500',
        'INCORRECT_P_A': '515',
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
            sys.stderr.write("User is not defined")
            exit(1)
        try:
            self.connection_parms['password'] = connection_parms['password']
        except KeyError:
            sys.stderr.write("Password is not defined")
            exit(1)
        self.connection_parms.update(connection_parms)
        if self.connection_parms['secure_login'] and self.connection_parms['webuser_login']:
            sys.stderr.write("You should enable only one of <secure_login> and <webuser_login>")
            exit(1)
        try:
            self.sock = socket.socket()
        except socket.error:
            sys.stderr.write('Failed to create socket')
            sys.exit()
        self.sock.settimeout(self.connection_parms['timeout'])
        self.sock.connect((self.connection_parms['host'], self.connection_parms['port']))
        result = self.sock.recv(1024)
        if self.getclicode(result) != self.CLI_CODE['OK']:
            print("Connect response code is not OK")
            sys.exit(1)
        self.sessionid = re.findall('(\<.*\@.*\>)', result)
        if self.connection_parms['ssl_transport']:
            self.check_response(self.send2cli("STLS"),"STLS")
            self.sock = ssl.wrap_socket(self.sock)
        else:
            pass
        if self.connection_parms['secure_login']:
            md5 = hashlib.md5()
            md5.update(self.sessionid[0])
            md5.update(self.connection_parms['password'])
            self.check_response(self.send2cli("APOP "+self.connection_parms['user']+" "+md5.hexdigest()), "APOP")
        elif self.connection_parms['webuser_login']:
            pass
            self.check_response(self.send2cli("AUTH WEBUSER " + self.connection_parms['user'] + " " + self.connection_parms['password']), "AUTH WEBUSER")
        else:
            if self.send2cli("USER " + self.connection_parms['user'])[0] != self.CLI_CODE['PASSWORD']:
                sys.stderr.write("USER response code is not PASSWORD")
                sys.exit(1)
            self.check_response(self.send2cli("PASS " + self.connection_parms['password']), "PASS")
        self.check_response(self.send2cli("INLINE"), "INLINE")

    def __del__(self):
        try:
            self.sock.close()
        except AttributeError:
            pass


    def getclicode(self, response):
        return re.findall('^(\d+)', response)[0]

    def getclimessage(self,response):
        return re.search('^(\d+) (.*)\\r', response).group(2)

    def send2cli(self, command):
        try:
            self.sock.sendall(bytes(command + "\r\n"))
        except socket.error:
            sys.stderr.write("send2cli <" + command + "> failed")
            sys.exit()
        result = self.sock.recv(1024)
        return (self.getclicode(result),result)

    def check_response(self, response, module):
        if response[0] != self.CLI_CODE['OK']:
            sys.stderr.write(module + " response code is " + response[0])
            sys.exit(1)

    def check_response_inline(self, response, module):
        if response[0] != self.CLI_CODE['OK_INLINE']:
            sys.stderr.write(module + " response code is " + response[0])
            sys.exit(1)

####################################################################
#    Account commands
####################################################################

    def ListDomainObjects(self, domain_name, limit, filter="", what="", cookie=""):
        commandline = "ListDomainObjects "+domain_name
        if filter != "":
            commandline += " FILTER "+ filter
        commandline +=  " " + str(limit)
        if what != "":
            commandline += " " + what
        if cookie != "":
            commandline += " COOKIE "+ cookie
        #pprint(commandline)
        result = self.send2cli(commandline)
        self.check_response_inline(result,"ListDomainObjects")
        res=()
        res = self.getclimessage(result[1])
        pprint(res)