#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import sys
import socket
import ssl
import re
import hashlib
import struct
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

    def __init__(self, connection_parms, default_domain=""):
        self.default_domain = default_domain
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
        if self.__getclicode(result) != self.CLI_CODE['OK']:
            print("Connect response code is not OK")
            sys.exit(1)
        self.sessionid = re.findall('(\<.*\@.*\>)', result)
        if self.connection_parms['ssl_transport']:
            self.__check_response(self.__send2cli("STLS"), "STLS")
            self.sock = ssl.wrap_socket(self.sock)
        else:
            pass
        if self.connection_parms['secure_login']:
            md5 = hashlib.md5()
            md5.update(self.sessionid[0])
            md5.update(self.connection_parms['password'])
            self.__check_response(self.__send2cli("APOP " + self.connection_parms['user'] + " " + md5.hexdigest()), "APOP")
        elif self.connection_parms['webuser_login']:
            pass
            self.__check_response(self.__send2cli(
                "AUTH WEBUSER " + self.connection_parms['user'] + " " + self.connection_parms['password']),
                "AUTH WEBUSER")
        else:
            if self.__send2cli("USER " + self.connection_parms['user'])[0] != self.CLI_CODE['PASSWORD']:
                sys.stderr.write("USER response code is not PASSWORD")
                sys.exit(1)
            self.__check_response(self.__send2cli("PASS " + self.connection_parms['password']), "PASS")
        self.__check_response(self.__send2cli("INLINE"), "INLINE")

    def __del__(self):
        try:
            self.sock.close()
        except AttributeError:
            pass



    def __getclicode(self, response):
        return re.findall('^(\d+)', response)[0]

    def __getclimessage(self, response):
        return re.search('^(\d+) (.*)\\r', response).group(2)

    def __send2cli(self, command, buffer_size=1024):
        try:
            self.sock.sendall(bytes(command + "\r\n"))
        except socket.error:
            sys.stderr.write("send2cli <" + command + "> failed")
            sys.exit()
        result = self.__recvall(self.sock,buffer_size)
        return (self.__getclicode(result), result)

    def __recvall(self, sock, n):
        data = b''
        packet = sock.recv(n)
        data += packet
        while '\n' not in packet:
            packet = sock.recv(n)
            data += str(packet)
        return data

    def __check_response(self, response, module):
        if response[0] != self.CLI_CODE['OK']:
            sys.stderr.write(module + " response code is " + response[0])
            sys.exit(1)

    def __check_response_inline(self, response, module):
        if response[0] != self.CLI_CODE['OK_INLINE']:
            sys.stderr.write(module + " response code is " + response[0])
            sys.exit(1)

    def __setdefaultdomain(self,domain_name):
        if domain_name == "":
            domain_name = self.default_domain
        return domain_name

    def __setdefaultdomainaddress(self,domain_name):
        domain_name = self.__setdefaultdomain(domain_name)
        if domain_name != "":
            domain_name = "@" + domain_name
        return domain_name

    def __parse_response(self, response):
        tmp = re.search('\{(.*)\}', self.__getclimessage(response)).group(1).split(";")
        tmp.remove('')
        result = {}
        for val in tmp:
            result[val.split("=")[0]] = val.split("=")[1]
        return result

    def __convert_param(self, param):
        result = "{"
        for value in param.items():
            result += value[0] + "=" + value[1] + ";"
        result += "}"
        return result

    ####################################################################
    #    Account commands
    ####################################################################

    def ListDomainObjects(self, limit, domain_name="", filter="", what="", cookie=""):
        domain_name = self.__setdefaultdomain(domain_name)
        commandline = "ListDomainObjects " + domain_name
        if filter != "":
            commandline += " FILTER " + filter
        commandline += " " + str(limit)
        if what != "":
            commandline += " " + what
        if cookie != "":
            commandline += " COOKIE " + cookie
        response = self.__send2cli(commandline)
        self.__check_response_inline(response, "ListDomainObjects")
        tmp = re.search('\((.*)\)', self.__getclimessage(response[1])).group(1).split(",")
        result = {}
        result["accounts"] = tmp[0]
        result["forwarders"] = tmp[-1]
        result["aliaces"] = tmp[-2]
        result["Objects"] = re.search('\{(.*)\}', self.__getclimessage(response[1])).group(1).split(";")
        return result

    def ListAccounts(self, domain_name=""):
        domain_name = self.__setdefaultdomain(domain_name)
        commandline = "ListAccounts " + domain_name
        response = self.__send2cli(commandline)
        self.__check_response_inline(response, "ListAccounts")
        tmp = re.search('{(.*)}', self.__getclimessage(response[1])).group(1).split(";")
        tmp.remove('')
        result = {}
        for lines in tmp:
            result[lines.split("=")[0]] = lines.split("=")[1]
        return result

    def ListDomainTelnums(self, limit, domain_name="", filter=""):
        domain_name = self.__setdefaultdomain(domain_name)
        commandline = "ListDomainTelnums " + domain_name
        if filter != "":
            commandline += " FILTER " + filter
        commandline += " " + str(limit)
        response = self.__send2cli(commandline)
        self.__check_response_inline(response, "ListDomainTelnums")
        return self.__parse_response(response[1])

    def CreateAccount(self, account_name, domain_name="", account_settings={}, account_type="", account_storage="",
                      legacy=False):
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "CreateAccount " + account_name
        commandline += domain_name
        if account_type != "":
            commandline += ' ' + account_type
        if account_storage != '':
            commandline += ' PATH ' + account_storage
        if legacy:
            commandline += ' LEGACY'
        commandline += ' {' + ";".join(["%s=\"%s\"" % (k, v) for k, v in account_settings.items()]) + ';}'
        response = self.__send2cli(commandline)
        self.__check_response(response, "CreateAccount")
        return True

    def RenameAccount(self, old_account_name, new_account_name, domain_name=""):
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "RenameAccount " + old_account_name + domain_name + " into " + new_account_name + domain_name
        response = self.__send2cli(commandline)
        self.__check_response(response, "CreateAccount")
        return True

    def DeleteAccount(self, account_name, domain_name=""):
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "DeleteAccount " + account_name + domain_name
        response = self.__send2cli(commandline)
        self.__check_response(response, "DeleteAccount")
        return True

    def SetAccountType(self, account_name, account_type, domain_name=""):
        if domain_name == "":
            domain_name = self.default_domain
        if domain_name != "":
            domain_name = "@" + domain_name
        commandline = "SetAccountType " + account_name + domain_name + account_type
        response = self.__send2cli(commandline)
        self.__check_response(response, "SetAccountType")
        return True

    def GetAccountSettings(self, account_name, domain_name=""):
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "GetAccountSettings " + account_name + domain_name
        response = self.__send2cli(commandline)
        self.__check_response_inline(response, "GetAccountSettings")
        return self.__parse_response(response[1])

    def UpdateAccountSettings(self, account_name, new_settings,domain_name=""):
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "UpdateAccountSettings " + account_name + domain_name + " " + self.__convert_param(new_settings)
        response = self.__send2cli(commandline)
        self.__check_response(response, "UpdateAccountSettings")
        return True

