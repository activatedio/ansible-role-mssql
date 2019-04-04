#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Ben Tomasini <btomasini@activated.io>
# Outline and parts are reused from mssql_db
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'activated'}


DOCUMENTATION = '''
---
module: mssql_loginuser
short_description: Add or remove MSSQL users and logins from a remote host.
description:
   - Add or remove MSSQL users and logins from a remote host.
version_added: "2.8"
options:
  name:
    description:
      - name of the user
    required: true
  login_name:
    description:
      - login to associate to the user
    required: true
  database:
    description:
      - Database for the user
    required: true
  roles:
    description:
      - List of roles to assign the user
    type: list
  login_user:
    description:
      - The username used to authenticate with
  login_password:
    description:
      - The password used to authenticate with
  login_host:
    description:
      - Host running the database
  login_port:
    description:
      - Port of the MSSQL server. Requires login_host be defined as other then localhost if login_port is used
    default: 1433
  state:
    description:
      - The database state
    default: present
    choices: [ "present", "absent" ]
notes:
   - Requires the pymssql Python package on the remote host. For Ubuntu, this
     is as easy as pip install pymssql (See M(pip).)
requirements:
   - python >= 2.7
   - pymssql
author: Ben Tomasini (@BenTomasini)
'''

EXAMPLES = '''
# Create a new login with name 'jack' and password 'supersecret'
- mssql_user:
    name: jack
    login_name: jack
    database: test
    roles:
      - db_owner
    state: present

'''

RETURN = '''
#
'''

import os
import traceback

PYMSSQL_IMP_ERR = None
try:
    import pymssql
except ImportError:
    PYMSSQL_IMP_ERR = traceback.format_exc()
    mssql_found = False
else:
    mssql_found = True

from ansible.module_utils.basic import AnsibleModule, missing_required_lib


def user_exists(conn, cursor, user):
    cursor.execute("SELECT name FROM sys.database_principals WHERE type = 'S' AND name = '%s'" % user)
    conn.commit()
    return bool(cursor.rowcount)


def user_create(conn, cursor, user, login, roles):
    cursor.execute("CREATE USER [%s] FROM LOGIN [%s]" % (user, login))
    if roles:
        for role in roles:
          cursor.execute("exec sp_addrolemember '%s', '%s'" % (role, user))
    return user_exists(conn, cursor, login)


def user_delete(conn, cursor, user):
    cursor.execute("DROP USER [%s]" % user)
    return not user_exists(conn, cursor, user)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=True),
            login_name=dict(required=True),
            database=dict(required=True),
            roles=dict(type='list'),
            login_user=dict(default=''),
            login_password=dict(default='', no_log=True),
            login_host=dict(required=True),
            login_port=dict(default='1433'),
            state=dict(
                default='present', choices=['present', 'absent'])
        )
    )

    if not mssql_found:
        module.fail_json(msg=missing_required_lib('pymssql'), exception=PYMSSQL_IMP_ERR)

    name = module.params['name']
    login_name = module.params['login_name']
    database = module.params['database']
    roles = module.params['roles']
    state = module.params['state']

    login_user = module.params['login_user']
    login_password = module.params['login_password']
    login_host = module.params['login_host']
    login_port = module.params['login_port']

    login_querystring = login_host
    if login_port != "1433":
        login_querystring = "%s:%s" % (login_host, login_port)

    if login_user != "" and login_password == "":
        module.fail_json(msg="when supplying login_user arguments login_password must be provided")

    try:
        conn = pymssql.connect(user=login_user, password=login_password, host=login_querystring, database=database)
        cursor = conn.cursor()
    except Exception as e:
        if "Unknown database" in str(e):
            errno, errstr = e.args
            module.fail_json(msg="ERROR: %s %s" % (errno, errstr))
        else:
            module.fail_json(msg="unable to connect, check login_user and login_password are correct, or alternatively check your "
                                 "@sysconfdir@/freetds.conf / ${HOME}/.freetds.conf")

    conn.autocommit(True)
    changed = False

    if user_exists(conn, cursor, name):
        if state == "absent":
            try:
                changed = user_delete(conn, cursor, name)
            except Exception as e:
                module.fail_json(msg="error deleting user: " + str(e))
    else:
        if state == "present":
            try:
                changed = user_create(conn, cursor, name, login_name, roles)
            except Exception as e:
                module.fail_json(msg="error creating user: " + str(e))

    module.exit_json(changed=changed, name=name, login_name=login_name, database=database, roles=roles)


if __name__ == '__main__':
    main()
