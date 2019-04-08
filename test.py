#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import cgpapi

def main():
    conn_parm = {
        'user': 'postmaster',
        'password': 'password',
        'ssl_transport': True,
    }

    connection = cgpapi.Cli(conn_parm)


if __name__ == '__main__':
    main()