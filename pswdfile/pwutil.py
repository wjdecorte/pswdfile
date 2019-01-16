#!/usr/local/bin/python2.7
"""
pwutil.py - This script will be used to maintain the password file.  Originally called pswdmain.py

@author:     Jason DeCorte

@copyright:  2015 DeCorte Industries, Inc. All rights reserved.

@license:

@contact:    jdecorte@decorteindustries.com

Version History:
0.01 jwd 01/20/2005
    Initial creation
0.02 jwd 08/31/2005
    Added new site specific library for company name
0.03 jwd 08/06/2007
    Updated default directories and fixed remove record bug
0.04 jwd 03/07/2014
    Ported to argparse
    Updated for new client
0.05 jwd 04/03/2015
    Updated to PEP 8 standard
0.06 jwd 10/28/2015
    Updated to use Python2.7
0.07 jwd 10/29/2015
    Changed menu to use npyscreen
    Removed command-line commands add, replace and delete (use menu option)
    Added check for adminuser
0.08 jwd 02/17/2016
    Add mode parameter to Password call
0.09 jwd3 03/01/2017
    Move code to main function for call from entry_point
    Fixed bug where deleted entries still showed in the list
    Changed filename to be a required argument
0.10 jwd3 05/05/2017
    Changed version to 0.xx where xx is sequential number - major/minor/revisions not needed
    Replaced argparse with click
    Removed adminuser check
"""
import sys
import os
import click

from pswdfile.password import Password
from pswdfile import __version__ as pkg_version

__version__ = "0.10"
__date__ = '01/20/2005'
__updated__ = '05/17/2017'


def upsert(filename,host,username,password):
    """Add entry or update if exists"""
    pwd = Password(data_file_dir=os.path.dirname(filename), data_file_name=os.path.basename(filename), mode='c')
    pwd.host = host
    pwd.username = username
    pwd.password = password
    pwd.encrypt()
    if pwd.is_error():
        return 1,pwd.get_error_message()
    else:
        return 0,None


@click.group()
@click.version_option(version=pkg_version)
def main():
    """Manage encrypted passwords for host and username in a file"""
    pass


@main.command()
@click.argument('filename',type=click.Path(dir_okay=False,resolve_path=True))
@click.argument('username')
@click.argument('host')
def get(filename,username,host):
    """Get the password for a host and username"""
    pwd = Password(data_file_dir=os.path.dirname(filename), data_file_name=os.path.basename(filename), mode='c')
    pwd.host = host
    pwd.username = username
    password = pwd.decrypt()
    if pwd.is_error():
        click.echo(pwd.get_error_message())
    else:
        click.echo(password)


@main.command()
@click.argument('filename',type=click.Path(dir_okay=False,resolve_path=True))
@click.argument('username')
@click.argument('host')
@click.argument('password')
def add(filename,username,host,password):
    """Add new entry in password file"""
    rc,errm = upsert(filename,host,username,password)
    if rc:
        message = "Failed to add entry [{hostname}/{username}]\n{errm}"
        message = message.format(errm=errm, hostname=host, username=username)
        click.echo(message)
    else:
        click.echo("Entry Added")


@main.command()
@click.argument('filename',type=click.Path(dir_okay=False,resolve_path=True))
@click.argument('username')
@click.argument('host')
@click.argument('password')
def update(filename,username,host,password):
    """Update existing entry in password file"""
    rc, errm = upsert(filename, host, username, password)
    if rc:
        message = "Failed to add/update entry [{hostname}/{username}]\n{errm}"
        message = message.format(errm=errm, hostname=host, username=username)
        click.echo(message)
    else:
        click.echo("Entry Updated")


@main.command()
@click.argument('filename',type=click.Path(dir_okay=False,resolve_path=True))
@click.argument('username')
@click.argument('host')
def remove(filename,username,host):
    """Remove entry from password file"""
    pwd = Password(data_file_dir=os.path.dirname(filename), data_file_name=os.path.basename(filename), mode='c')
    pwd.host = host
    pwd.username = username
    pwd.remove_record()
    if pwd.is_error():
        message = "Failed to remove entry [{hostname}/{username}]\n{em}".format(em=pwd.get_error_message(),
                                                                                hostname=host,
                                                                                username=username)
        click.echo(message)
    else:
        click.echo("Entry Deleted")


@main.command()
@click.argument('filename',type=click.Path(dir_okay=False,resolve_path=True))
def list(filename):
    """List entries in password file"""
    pwd = Password(data_file_dir=os.path.dirname(filename), data_file_name=os.path.basename(filename), mode='c')
    record_list = pwd.get_all()
    if pwd.is_error():
        message = "Failed to get all entries from the file\n{em}".format(em=pwd.get_error_message())
        click.echo(message)
    else:
        for entry in record_list:
            click.echo("{}@{}".format(entry.get('username'),entry.get('host')))


if __name__ == '__main__':
    main()
