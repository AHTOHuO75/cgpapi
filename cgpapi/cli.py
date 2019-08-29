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

    def __init__(self, connection_parms, default_domain="", verbose=0):
        """
        Class initialization
        :param connection_parms: List of parameter for connection.
            Required parameters:
                user
                password
            Optional parameters(has deafult values):
                host
                port
                ssl_transport
                secure_login
                webuser_login
                timeout
        :param default_domain: domain in which you prefer to find users, get or change domain parameters.
        :param verbose: Verbosity level of output. At a moment it has two values - 0 and 1,
            and affects only on command response of CLI(just code ore code and message).
        """
        self.verbose = verbose
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
            # Only one of login (secure or webuser) can be defined.
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
        """Class destructor. Closes socket."""
        try:
            self.sock.close()
        except AttributeError:
            pass



    def __getclicode(self, response):
        """
        Gets CLI code of command response.
        :param response: response message from CLI.
        :return:
        """
        """
            Getting CLI code of command response.
                response - response message from CLI.
            Returns string.
        """
        return re.findall('^(\d+)', response)[0]

    def __getclimessage(self, response):
        """
        Gets CLI message of command response.
        :param response: response - response message from CLI.
        :return: string
        """
        return re.search('^(\d+) (.*)\\r', response).group(2)

    def __send2cli(self, command, buffer_size=1024):
        """
        Sends command to CLI.
        :param command: command whicj you whant to send.
        :param buffer_size: size of buffer for getting data from socket(default: 1024).
        :return: list.
        """
        try:
            self.sock.sendall(bytes(command + "\r\n"))
        except socket.error:
            sys.stderr.write("send2cli <" + command + "> failed")
            sys.exit()
        result = self.__recvall(self.sock,buffer_size)
        return (self.__getclicode(result), result)

    def __recvall(self, sock, n):
        """
        Receivs all values from socket.
        :param sock: socket object.
        :param n: size of portion for getting data from socket.
        :return: string.
        """
        data = b''
        packet = sock.recv(n)
        data += packet
        while '\n' not in packet:
            # Data from socket ends with '\n'
            packet = sock.recv(n)
            data += str(packet)
        return data

    def __check_response(self, response, module):
        """
        Checks response from CLI. Exits if status code is not OK.
        :param response: list received from __send2cli.
        :param module: calling function name(e.g. ListDomainObjects).String.
        :return:
        """
        if self.verbose == 0:
            response_result = response[0]
        else:
            response_result = response[1]
        if response[0] != self.CLI_CODE['OK']:
            sys.stderr.write(module + " response code is " + response_result)
            sys.exit(1)

    def __check_response_inline(self, response, module):
        """
        Checks response from CLI for INLINE. Exits if status code is not OK_INLINE.
        :param response: list received from __send2cli.
        :param module: calling function name(e.g. ListDomainObjects).String.
        :return:
        """
        if self.verbose == 0:
            response_result = response[0]
        else:
            response_result = response[1]
        if response[0] != self.CLI_CODE['OK_INLINE']:
            sys.stderr.write(module + " response code is " + response[0])
            sys.exit(1)

    def __setdefaultdomain(self,domain_name):
        """
        Sets defult domain for commands.
        :param domain_name: name of target domain.
        :return: string.
        """
        if domain_name == "":
            domain_name = self.default_domain
        return domain_name

    def __setdefaultdomainaddress(self,domain_name):
        """
        Sets default domain with leading '@'
        :param domain_name: name of target domain.
        :return: string.
        """
        domain_name = self.__setdefaultdomain(domain_name)
        if domain_name != "":
            domain_name = "@" + domain_name
        return domain_name

    def __parse_response(self, response):
        """
        Parses response from CLI. Depending on the return string it returns list or dict.
        If return parameters in round brackets ('()') method returns list, and if parameters in braces('{}')
        it returns dict.
        :param response: response message from CLI.
        :return: dict or list.
        """
        if re.search('\{(.*)\}',self.__getclimessage(response)) != None:
            tmp = re.search('[\{\(](.*)[\}\)]', self.__getclimessage(response)).group(1).split(";")
            if '' in tmp:
                tmp.remove('')
            result = {}
            for val in tmp:
                result[val.split("=")[0]] = val.split("=")[1]
        if re.search('\((.*)\)',self.__getclimessage(response)) != None:
            tmp = re.search('[\{\(](.*)[\}\)]', self.__getclimessage(response)).group(1).split(",")
            if '' in tmp:
                tmp.remove('')
            result = tmp
        return result

    def __convert_param(self, param):
        """
        Converts input parameters for methods into string from list or dict.
        If parameter is list method wraps result in round brackets ('()').
        If parameter is dict method wraps result in braces ('{}').
        :param param:
        :return: string.
        """
        if type(param) == list:
            result = "("
            for value in param:
                result +=value + ","
            result = result[0:-1]
            result += ")"
        if type(param) == dict:
            result = "{"
            for value in param.items():
                result += value[0] + "=" + value[1] + ";"
            result += "}"
        return result

    ####################################################################
    #    Account commands
    ####################################################################

    def ListDomainObjects(self, limit, domain_name="", filter="", what="", cookie=""):
        """
        Gets the list of domain objects.
        :param limit: limit of processing object to list(integer).
        :param domain_name: optional name of target domain.
        :param filter: optional parameter specifies a filter string: only objects with names including this string as a substring are listed.
        :param what: optionsl keywords specify which Domain objects should be listed(ACCOUNTS, ALIASES, FORWARDERS).
        :param cookie: ptional parameter specifies a "cookie" string.
        :return:
        """
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
        """
        Gets list of Accounts in the Domain.
        :param domain_name: optional name of target domain.
        :return: dict.
        """
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
        """
        Reads Telnum numbers created in the specified Domain.
        :param limit: the maximum number of Telnum numbers to return.
        :param domain_name: optional name of target domain.
        :param filter: if this optional parameter is specified, only the telnum numbers containing the specified string are returned.
        :return: dict.
        """
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
        """
        Creates Account.
        :param account_name: string.
        :param domain_name: optional parameter, which specifies Domain for Account.
        :param account_settings: dict - specifies the initial Account settings.
                                 Account is created using the settings specified in the Account Template for the target Domain.
                                 If the settings parameter is specified, it is used to modify the Template settings.
        :param account_type: optional parameter specifies the type of the Account to create.
                             (MultiMailbox | TextMailbox | MailDirMailbox | SlicedMailbox | AGrade | BGrade | CGrade)
                             If no Account type is specified a MultiMailbox-type Account is created.
        :param account_storage: optional parameter specifies the "storage mount Point" directory for the Account data
                                (the name should be specified without the .mnt suffix).
        :param legacy: optional flag tells the system to create an Account with a Legacy (visible for legacy mailers) INBOX.
        :return: true.
        """
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
        """
        Renames target Account.
        :param old_account_name: name of an existing Account.
        :param new_account_name: new Account name.
        :param domain_name: optional parameter, which specifies Domain of Account.
        :return: true.
        """
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "RenameAccount " + old_account_name + domain_name + " into " + new_account_name + domain_name
        response = self.__send2cli(commandline)
        self.__check_response(response, "CreateAccount")
        return True

    def DeleteAccount(self, account_name, domain_name=""):
        """
        Deletes target Account.
        :param account_name: parameter specifies the name of an existing Account.
        :param domain_name: optional parameter, which specifies Domain of Account.
        :return: true.
        """
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "DeleteAccount " + account_name + domain_name
        response = self.__send2cli(commandline)
        self.__check_response(response, "DeleteAccount")
        return True

    def SetAccountType(self, account_name, account_type, domain_name=""):
        """
        Sets Account type.
        :param account_name: specifies the name of an existing Account.
        :param account_type: parameter specifies the new Account type.
                             (MultiMailbox | AGrade | BGrade | CGrade)
        :param domain_name: optional parameter, which specifies Domain of Account.
        :return: true.
        """
        if domain_name == "":
            domain_name = self.default_domain
        if domain_name != "":
            domain_name = "@" + domain_name
        commandline = "SetAccountType " + account_name + domain_name + account_type
        response = self.__send2cli(commandline)
        self.__check_response(response, "SetAccountType")
        return True

    def GetAccountSettings(self, account_name, domain_name=""):
        """
        Gets the Account settings.
        :param account_name: specifies the name of an existing Account.
        :param domain_name: optional parameter, which specifies Domain of Account.
        :return: list.
        """
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "GetAccountSettings " + account_name + domain_name
        response = self.__send2cli(commandline)
        self.__check_response_inline(response, "GetAccountSettings")
        return self.__parse_response(response[1])

    def GetAccountEffectiveSettings(self, account_name, domain_name=""):
        """
        Gets the Account effective settings.
        :param account_name: specifies the name of an existing Account.
        :param domain_name: optional parameter, which specifies Domain of Account.
        :return: list.
        """
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "GetAccountEffectiveSettings " + account_name + domain_name
        response = self.__send2cli(commandline)
        self.__check_response_inline(response, "GetAccountEffectiveSettings")
        return self.__parse_response(response[1])

    def UpdateAccountSettings(self, account_name, new_settings,domain_name=""):
        """
        Updates the Account settings.
        :param account_name: specifies the name of an existing Account.
        :param new_settings: dict is used to update the Account settings dictionary.
                             It does not have to contain all settings data, the omitted settings will be left unmodified.
                             If a new setting value is specified as the string default, the Account setting value is removed,
                             so the default Account setting value will be used.
        :param domain_name: optional parameter, which specifies Domain of Account.
        :return: true.
        """
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "UpdateAccountSettings " + account_name + domain_name + " " + self.__convert_param(new_settings)
        response = self.__send2cli(commandline)
        self.__check_response(response, "UpdateAccountSettings")
        return True

    def SetAccountSettings(self, account_name, new_settings,domain_name=""):
        """
        Sets the Account settinga.
        :param account_name: specifies the name of an existing Account.
        :param new_settings: dictionary is used to replace the Account settings dictionary.
                             All old Account settings are removed.
        :param domain_name: optional parameter, which specifies Domain of Account.
        :return: true.
        """
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "SetAccountSettings " + account_name + domain_name + " " + self.__convert_param(new_settings)
        response = self.__send2cli(commandline)
        self.__check_response(response, "SetAccountSettings")
        return True

    def SetAccountPassword(self, account_name, new_password,domain_name="", check=False, method=""):
        """
        Sets or updates the Account password.
        :param account_name: specifies the name of an existing Account.
        :param new_password: string specifies the new Account password.
                             The new password will be stored using the effective Password Encryption setting of the target Account.
        :param domain_name: optional parameter, which specifies Domain of Account.
        :param check: optional boolean parameter with default value "false".
                      Any user can modify her own Account password.
                      In this case, or when the check is true , the operation succeeds only if the the supplied password
                      matches the size and complexity restrictions and the Account CanModifyPassword effective Setting is enabled.
        :param method: optional string parameter specifies the Account Access Mode.
                       If this mode is "SIP", the the Alternative SIP Password Setting is modified,
                       if this mode is RADIUS, then the Alternative RADIUS Password Setting is modified.
                       In all other cases, the CommuniGate Password setting is modified.
                       The new password will be stored using the effective Password Encryption setting of the target Account.
        :return: true.
        """
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "SetAccountPassword " + account_name + domain_name + " PASSWORD " + new_password
        if method != "":
            commandline += " METHOD " + method
        if check:
            commandline += " CHECK"
        response = self.__send2cli(commandline)
        self.__check_response(response, "SetAccountPassword")
        return True

    def VerifyAccountPassword(self, account_name, password,domain_name=""):
        """
        Veryfies the Account password.
        :param account_name: specifies the name of an existing Account.
        :param password: string is used to specify the password to check (in the clear text format).
        :param domain_name: optional parameter, which specifies Domain of Account.
        :return: true.
        """
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "VerifyAccountPassword " + account_name + domain_name + " PASSWORD " + password
        response = self.__send2cli(commandline)
        self.__check_response(response, "VerifyAccountPassword")
        return True

    def GetAccountAliases(self, account_name, domain_name=""):
        """
        Gets the Account aliases.
        :param account_name: specifies the name of an existing Account.
        :param domain_name: optional parameter, which specifies Domain of Account.
        :return: list.
        """
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "GetAccountAliases " + account_name + domain_name
        response = self.__send2cli(commandline)
        self.__check_response_inline(response, "GetAccountAliases")
        return self.__parse_response(response[1])

    def SetAccountAliases(self, account_name, new_aliases,domain_name=""):
        """
        Sets the Account aliases.
        :param account_name: specifies the name of an existing Account.
        :param new_aliases: list.
        :param domain_name: optional parameter, which specifies Domain of Account.
        :return:
        """
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "SetAccountAliases " + account_name + domain_name + " " + self.__convert_param(new_aliases)
        response = self.__send2cli(commandline)
        self.__check_response(response, "SetAccountAliases")
        return True

    def GetAccountTelnums(self, account_name, domain_name=""):
        """
        Gets the Account telephone numbers.
        :param account_name: specifies the name of an existing Account.
        :param domain_name: optional parameter, which specifies Domain of Account.
        :return: list.
        """
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "GetAccountTelnums " + account_name + domain_name
        response = self.__send2cli(commandline)
        self.__check_response_inline(response, "GetAccountTelnums")
        return self.__parse_response(response[1])

    def SetAccountTelnums(self, account_name, new_telnums,domain_name=""):
        """
        Sets the Account telephone numbers.
        :param account_name: specifies the name of an existing Account.
        :param new_telnums: list. All old numbers assigned to the Account are removed.
        :param domain_name: optional parameter, which specifies Domain of Account.
        :return:
        """
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "SetAccountTelnums " + account_name + domain_name + " " + self.__convert_param(new_telnums)
        response = self.__send2cli(commandline)
        self.__check_response(response, "SetAccountTelnums")
        return True

    def GetAccountMailRules(self, account_name, domain_name=""):
        """
        Gets the Account incoming mail rules.
        :param account_name: specifies the name of an existing Account.
        :param domain_name: optional parameter, which specifies Domain of Account.
        :return: list or dict.
        """
        """In progress. Need to convert to convenient dict."""
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "GetAccountMailRules " + account_name + domain_name
        response = self.__send2cli(commandline)
        self.__check_response_inline(response, "GetAccountMailRules")
        return self.__parse_response(response[1])

    def SetAccountMailRules(self, account_name, new_mailrules,domain_name=""):
        """In progress. Need to convert to convenient dict."""
        domain_name = self.__setdefaultdomainaddress(domain_name)
        commandline = "SetAccountMailRules " + account_name + domain_name + " " + self.__convert_param(new_mailrules)
        #response = self.__send2cli(commandline)
        #self.__check_response(response, "SetAccountMailRules")
        return True