#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import cgpapi

def main():
    conn_parm = {
        'user': 'postmaster',
        'password': 'password',
        'ssl_transport': True,
        'secure_login': True,
        'webuser_login': False
    }

    cli = cgpapi.Cli(conn_parm)
    cli.ListDomainObjects("krwtest.rzd", 20, "", "ACCOUNTS ALIASES FORWARDERS")

if __name__ == '__main__':
    main()