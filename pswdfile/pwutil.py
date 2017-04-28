#!/usr/local/bin/python2.7
"""
pwutil.py - This script will be used to maintain the password file.  Originally called pswdmain.py

@author:     Jason DeCorte

@copyright:  2015 Equifax. All rights reserved.

@license:    Apache License 2.0

@contact:    jason.decorte@equifax.com

Version History:
1.0 jwd 01/20/2005
    Initial creation
1.1 jwd 08/31/2005
    Added new site specific library for company name
1.2 jwd 08/06/2007
    Updated default directories and fixed remove record bug
2.0 jwd 03/07/2014
    Ported to argparse
    Updated for new client
2.1 jwd 04/03/2015
    Updated to PEP 8 standard
2.2 jwd 10/28/2015
    Updated to use Python2.7
2.3 jwd 10/29/2015
    Changed menu to use npyscreen
    Removed command-line commands add, replace and delete (use menu option)
    Added check for adminuser
2.4 jwd 02/17/2016
    Add mode parameter to Password call
2.5 jwd3 03/01/2017
    Move code to main function for call from entry_point
"""
import sys
import os
import argparse
import npyscreen
from getpass import getuser
import curses.ascii

from password import Password

__version__ = "2.5"
__date__ = '01/20/2005'
__updated__ = '03/01/2017'
__all__ = []


# Classes
class ActionGridColTitles(npyscreen.GridColTitles):
    """
    New widget that makes a grid actionable
    """
    # def display_value(self, value):
    #     return [value.get('hostname'),value.get('username')]

    def set_up_handlers(self):
        super(ActionGridColTitles, self).set_up_handlers()
        self.handlers.update({curses.ascii.NL:self.h_act_on_highlighted,
                              curses.ascii.CR:self.h_act_on_highlighted,
                              ord('x'):self.h_act_on_highlighted,
                              curses.ascii.SP:self.h_act_on_highlighted,
                              "^A": self.when_add_source,
                              "^D": self.when_delete_source})

    def actionHighlighted(self, act_on_this, keypress):
        self.parent.parentApp.getForm('VIEWFORM').entry_record = {'hostname':act_on_this[0],
                                                                  'username':act_on_this[1],
                                                                  'password':pwd.decrypt(act_on_this[2])}
        self.parent.parentApp.switchForm('VIEWFORM')

    def h_act_on_highlighted(self, ch):
        try:
            return self.actionHighlighted(self.values[self.edit_cell[0]], ch)
        except IndexError:
            raise

    def when_add_source(self, *args, **keywords):
        viewform = self.parent.parentApp.getForm('VIEWFORM')
        viewform.hostname.value = None
        viewform.username.value = None
        viewform.password.value = None
        viewform.entry_record = None
        self.parent.parentApp.switchForm('VIEWFORM')

    def when_delete_source(self, *args, **keywords):
        hostname = self.values[self.edit_cell[0]][0]
        username = self.values[self.edit_cell[0]][1]
        message = "Are you sure you want to delete the entry [{hostname}/{username}]?".format(hostname=hostname,
                                                                                              username=username)
        if npyscreen.notify_yes_no(message,title="Confirm Deletion",editw=1):
            pwd.set_hostname(hostname)
            pwd.set_username(username)
            pwd.remove_record()
            if pwd.is_error():
                message = "Failed to remove entry [{hostname}/{username}]\n{em}".format(em=pwd.get_error_message(),
                                                                                        hostname=hostname,
                                                                                        username=username)
                npyscreen.notify_confirm(message=message,title="ERROR",editw=1)
            else:
                npyscreen.notify_wait(message="Entry Deleted")


class ViewForm(npyscreen.ActionPopup):
    """
    Form for viewing entry
    """
    def create(self):
        """
        Define widgets for form creation
        """
        self.entry_record = None
        self.hostname = self.add(npyscreen.TitleText,
                                 name="Host Name:")
        self.username = self.add(npyscreen.TitleText,
                                 name='User Name:')
        self.password = self.add(npyscreen.TitleText,
                                 name="Password:")

    def beforeEditing(self):
        if self.entry_record:
            self.hostname.value = self.entry_record.get('hostname')
            self.username.value = self.entry_record.get('username')
            self.password.value = self.entry_record.get('password')

    def on_ok(self):
        if self.hostname.value and self.username.value and self.password.value:
            if (not self.entry_record or (self.hostname.value != self.entry_record.get('hostname')
                                          or self.username.value != self.entry_record.get('username')
                                          or self.password.value != self.entry_record.get('password'))):
                pwd.set_hostname(self.hostname.value)
                pwd.set_username(self.username.value)
                pwd.set_password(self.password.value)
                pwd.encrypt()
                if pwd.is_error():
                    message = "Failed to add/update entry [{hostname}/{username}]\n{errm}"
                    message = message.format(errm=pwd.get_error_message(),
                                             hostname=self.hostname.value,
                                             username=self.username.value)
                    npyscreen.notify_confirm(message=message,title="ERROR",editw=1)
                else:
                    npyscreen.notify_wait(message="Entry Added/Updated")
            self.parentApp.switchFormPrevious()
        else:
            npyscreen.notify_confirm(title="Missing Data",
                                     message="Please enter a value for all fields",
                                     editw=1)

    def on_cancel(self):
        self.parentApp.switchFormPrevious()


class MainForm(npyscreen.ActionFormMinimal):
    """
    Main Form for display metadata and artifacts
    """
    OK_BUTTON_TEXT = "EXIT"

    def create(self):
        """
        Define widgets for form creation
        """
        help_list = ["Select an entry in the list to view and/or edit by pressing Enter or Space.",
                     "Press Ctrl-A to add a new entry.",
                     "Press Ctrl-D to delete an entry."]
        self.help = "\n".join(help_list)

        self.add(npyscreen.TitleFixedText,
                 name="Version:",
                 value="{0}".format(__version__),
                 begin_entry_at=12,
                 editable=False,
                 #use_two_lines=False,
                 max_width=20,
                 max_height=1,
                 relx=2)
        self.add(npyscreen.TitleFixedText,
                 name="Build Date:",
                 value=__updated__,
                 begin_entry_at=14,
                 editable=False,
                 #use_two_lines=False,
                 max_width=27,
                 max_height=1,
                 relx=-30,
                 rely=2)
        self.nextrely += 2
        self.add(npyscreen.TitleFixedText,
                 name="Commands:",
                 value="^A=Add  ^D=Delete",
                 begin_entry_at=12,
                 # relx=5,
                 editable=False,)
        self.nextrely += 1
        self.entry_list = self.add(ActionGridColTitles,
                                   name="Connection Entries",
                                   col_titles=['HOST','USER'],
                                   columns=2,
                                   column_width=50,
                                   always_show_cursor=True,
                                   select_whole_line=True)

    def beforeEditing(self):
        record_list = pwd.get_all()
        self.entry_list.values = [[x.get('host'),x.get('username'),x.get('rsakey')] for x in record_list]

    def on_ok(self):
        self.parentApp.setNextForm(None)
        self.editing = False
        self.parentApp.switchFormNow()


class MenuApp(npyscreen.NPSAppManaged):
    """
    Interactive Menu app
    """

    def onStart(self):
        """
        Define forms in app
        """
        self.addForm("MAIN", MainForm, name="P a s s W o r d   U T I L i t y")
        self.addForm("VIEWFORM", ViewForm,
                     name="Connection Entry")


# Functions
def interactive_menu(args,pwd):
    app = MenuApp()
    app.run()
    return "Interactive menu exited\n"


def get(args,pwd):
    pwd.set_hostname(args.host)
    pwd.set_username(args.user)
    pword = pwd.decrypt()
    if pwd.is_error():
        return pwd.get_error_message() + "\n"
    else:
        return pword + "\n"


def main():
    """
       M  A  I  N
    """
    # check user credentials
    if sys.platform == 'linux2':
        adminuser = 660 in os.getgroups()
    elif sys.platform == 'win32':
        user = getuser()
        adminuser = user in ['jwd3']
    else:
        adminuser = False
    if not adminuser:
        sys.stdout.write("Invalid user!!  Must be in Admin group!!\n")
        return 1
    parser = argparse.ArgumentParser(prog='pwutil',description='Password Maintenance Utility')
    parser.add_argument('-V','--version', action='version', version='%(prog)s ' + __version__)
    subparsers = parser.add_subparsers(title='Commands',description='Possible Actions', help='Command Help')
    parser_m = subparsers.add_parser('menu', help='Use interactive menu')
    parser_m.add_argument('path', action='store', help='location in the file system of the data file')
    parser_m.add_argument('-f','--filename', action='store', help='name of the data file containing the encrypted object')
    parser_m.set_defaults(func=interactive_menu)
    parser_g = subparsers.add_parser('get', help='Get password for existing user and host (optional)')
    parser_g.add_argument('path', action='store', help='location in the file system of the data file')
    parser_g.add_argument('user', action='store', help='Name of user')
    parser_g.add_argument('-f','--filename', action='store', help='name of the data file containing the encrypted object')
    parser_g.add_argument('-t','--host', action='store', help='Name of host')
    parser_g.set_defaults(func=get)
    cli_args = parser.parse_args()

    pwd = Password(data_file_dir=cli_args.path,data_file_name=cli_args.filename,mode='c')
    sys.stdout.write(cli_args.func(cli_args,pwd))
    return 0

if __name__ == '__main__':
    sys.exit(main())
