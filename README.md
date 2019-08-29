

This python module implements integration with CommuniGate Pro CLI API.
 
 **Classes**

`      `

 

[Cli](cli.html#Cli)

 
 class **Cli**

`   `

 

Methods defined here:

**CreateAccount**(self, account\_name, domain\_name='', account\_settings={}, account\_type='', account\_storage='', legacy=False)  
`Creates Account. :param account_name: string. :param domain_name: optional parameter, which specifies Domain for Account. :param account_settings: dict - specifies the initial Account settings.                          Account is created using the settings specified in the Account Template for the target Domain.                          If the settings parameter is specified, it is used to modify the Template settings. :param account_type: optional parameter specifies the type of the Account to create.                      (MultiMailbox | TextMailbox | MailDirMailbox | SlicedMailbox | AGrade | BGrade | CGrade)                      If no Account type is specified a MultiMailbox-type Account is created. :param account_storage: optional parameter specifies the "storage mount Point" directory for the Account data                         (the name should be specified without the .mnt suffix). :param legacy: optional flag tells the system to create an Account with a Legacy (visible for legacy mailers) INBOX. :return: true.`

**DeleteAccount**(self, account\_name, domain\_name='')  
`Deletes target Account. :param account_name: parameter specifies the name of an existing Account. :param domain_name: optional parameter, which specifies Domain of Account. :return: true.`

**GetAccountAliases**(self, account\_name, domain\_name='')  
`Gets the Account aliases. :param account_name: specifies the name of an existing Account. :param domain_name: optional parameter, which specifies Domain of Account. :return: list.`

**GetAccountEffectiveSettings**(self, account\_name, domain\_name='')  
`Gets the Account effective settings. :param account_name: specifies the name of an existing Account. :param domain_name: optional parameter, which specifies Domain of Account. :return: list.`

**GetAccountMailRules**(self, account\_name, domain\_name='')  
`Gets the Account incoming mail rules. :param account_name: specifies the name of an existing Account. :param domain_name: optional parameter, which specifies Domain of Account. :return: list or dict.`

**GetAccountSettings**(self, account\_name, domain\_name='')  
`Gets the Account settings. :param account_name: specifies the name of an existing Account. :param domain_name: optional parameter, which specifies Domain of Account. :return: list.`

**GetAccountTelnums**(self, account\_name, domain\_name='')  
`Gets the Account telephone numbers. :param account_name: specifies the name of an existing Account. :param domain_name: optional parameter, which specifies Domain of Account. :return: list.`

**ListAccounts**(self, domain\_name='')  
`Gets list of Accounts in the Domain. :param domain_name: optional name of target domain. :return: dict.`

**ListDomainObjects**(self, limit, domain\_name='', filter='', what='', cookie='')  
`Gets the list of domain objects. :param limit: limit of processing object to list(integer). :param domain_name: optional name of target domain. :param filter: optional parameter specifies a filter string: only objects with names including this string as a substring are listed. :param what: optionsl keywords specify which Domain objects should be listed(ACCOUNTS, ALIASES, FORWARDERS). :param cookie: ptional parameter specifies a "cookie" string. :return:`

**ListDomainTelnums**(self, limit, domain\_name='', filter='')  
`Reads Telnum numbers created in the specified Domain. :param limit: the maximum number of Telnum numbers to return. :param domain_name: optional name of target domain. :param filter: if this optional parameter is specified, only the telnum numbers containing the specified string are returned. :return: dict.`

**RenameAccount**(self, old\_account\_name, new\_account\_name, domain\_name='')  
`Renames target Account. :param old_account_name: name of an existing Account. :param new_account_name: new Account name. :param domain_name: optional parameter, which specifies Domain of Account. :return: true.`

**SetAccountAliases**(self, account\_name, new\_aliases, domain\_name='')  
`Sets the Account aliases. :param account_name: specifies the name of an existing Account. :param new_aliases: list. :param domain_name: optional parameter, which specifies Domain of Account. :return:`

**SetAccountMailRules**(self, account\_name, new\_mailrules, domain\_name='')  
`In progress. Need to convert to convenient dict.`

**SetAccountPassword**(self, account\_name, new\_password, domain\_name='', check=False, method='')  
`Sets or updates the Account password. :param account_name: specifies the name of an existing Account. :param new_password: string specifies the new Account password.                      The new password will be stored using the effective Password Encryption setting of the target Account. :param domain_name: optional parameter, which specifies Domain of Account. :param check: optional boolean parameter with default value "false".               Any user can modify her own Account password.               In this case, or when the check is true , the operation succeeds only if the the supplied password               matches the size and complexity restrictions and the Account CanModifyPassword effective Setting is enabled. :param method: optional string parameter specifies the Account Access Mode.                If this mode is "SIP", the the Alternative SIP Password Setting is modified,                if this mode is RADIUS, then the Alternative RADIUS Password Setting is modified.                In all other cases, the CommuniGate Password setting is modified.                The new password will be stored using the effective Password Encryption setting of the target Account. :return: true.`

**SetAccountSettings**(self, account\_name, new\_settings, domain\_name='')  
`Sets the Account settinga. :param account_name: specifies the name of an existing Account. :param new_settings: dictionary is used to replace the Account settings dictionary.                      All old Account settings are removed. :param domain_name: optional parameter, which specifies Domain of Account. :return: true.`

**SetAccountTelnums**(self, account\_name, new\_telnums, domain\_name='')  
`Sets the Account telephone numbers. :param account_name: specifies the name of an existing Account. :param new_telnums: list. All old numbers assigned to the Account are removed. :param domain_name: optional parameter, which specifies Domain of Account. :return:`

**SetAccountType**(self, account\_name, account\_type, domain\_name='')  
`Sets Account type. :param account_name: specifies the name of an existing Account. :param account_type: parameter specifies the new Account type.                      (MultiMailbox | AGrade | BGrade | CGrade) :param domain_name: optional parameter, which specifies Domain of Account. :return: true.`

**UpdateAccountSettings**(self, account\_name, new\_settings, domain\_name='')  
`Updates the Account settings. :param account_name: specifies the name of an existing Account. :param new_settings: dict is used to update the Account settings dictionary.                      It does not have to contain all settings data, the omitted settings will be left unmodified.                      If a new setting value is specified as the string default, the Account setting value is removed,                      so the default Account setting value will be used. :param domain_name: optional parameter, which specifies Domain of Account. :return: true.`

**VerifyAccountPassword**(self, account\_name, password, domain\_name='')  
`Veryfies the Account password. :param account_name: specifies the name of an existing Account. :param password: string is used to specify the password to check (in the clear text format). :param domain_name: optional parameter, which specifies Domain of Account. :return: true.`

**\_\_del\_\_**(self)  
`Class destructor. Closes socket.`

**\_\_init\_\_**(self, connection\_parms, default\_domain='', verbose=0)  
`Class initialization :param connection_parms: List of parameter for connection.     Required parameters:         user         password     Optional parameters(has deafult values):         host         port         ssl_transport         secure_login         webuser_login         timeout :param default_domain: domain in which you prefer to find users, get or change domain parameters. :param verbose: Verbosity level of output. At a moment it has two values - 0 and 1,     and affects only on command response of CLI(just code ore code and message).`

* * * * *

Data and other attributes defined here:

**CLI\_CODE** = {'GEN\_ERR': '501', 'INCORRECT\_P\_A': '515', 'OK': '200', 'OK\_INLINE': '201', 'PASSWORD': '300', 'STRANGE': '10000', 'UNKNOWN\_USER': '500'}

**connection\_parms** = {'host': 'localhost', 'password': '', 'port': 106, 'secure\_login': True, 'ssl\_transport': False, 'timeout': 295, 'user': '', 'webuser\_login': False}
