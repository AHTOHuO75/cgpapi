#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import cgpapi
from pprint import pprint

def main():
    conn_parm = {
        'user': 'postmaster',
        'password': 'password',
        'ssl_transport': True,
        'secure_login': True,
        'webuser_login': False
    }

    cli = cgpapi.Cli(conn_parm,"krwtest.rzd")
    #pprint(cli.ListDomainObjects(20, "krwtest.rzd", what="ACCOUNTS ALIASES FORWARDERS"))
    #pprint(cli.ListAccounts())
    #pprint(cli.ListDomainTelnums( 20))
    #cli.CreateAccount("test_from_python", "krwtest.rzd", account_type="SlicedMailbox", account_settings={"RealName": "It is a Real Name", "MaxAccountSize": "100K"})
    #cli.RenameAccount("test_from_python","test_from_python1")
    #cli.DeleteAccount("test_from_python1")
    #pprint(cli.GetAccountSettings("test-kozh"))
    new_settings = {
        'MaxAccountSize': '100K',
        'RealName': '"Real Name from UPDATE PYTHON"',
        'ServiceClass': 'MAIL',
    }
    cli.UpdateAccountSettings("test-kozh",new_settings)

if __name__ == '__main__':
    main()