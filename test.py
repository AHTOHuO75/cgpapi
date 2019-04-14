#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import cgpapi

def main():
    conn_parm = {
        'user': 'postmaster',
        'password': '123',
        'ssl_transport': True,
        'secure_login': True,
        'webuser_login': False
    }

    cli = cgpapi.Cli(conn_parm)
    #cli.ListDomainObjects("test.esrr.rzd", 20, "", "ACCOUNTS ALIASES FORWARDERS")
    #cli.ListAccounts("test.esrr.rzd")
    #cli.ListDomainTelnums("test.esrr.rzd", 20, "")
    cli.CreateAccount("test_from_python", "testmail.esrr.rzd", account_storage="store01",account_type="SlicedMailbox", account_settings={"RealName": "It is a Real Name", "MaxAccountSize": "100K"})

if __name__ == '__main__':
    main()