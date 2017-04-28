"""
  Name: password.py

  Purpose: This class is contains methods to encrypt and decrypt passwords per
           database and username combination.
  !!!!WARNING!!!! This class is not secure enough for any type of highly sensitive data
                  and is only met for use on casual applications to keep passwords from
                  being stored in ASCII plain text format.  Implement with AES128 for
                  complete security.

@author:     Jason DeCorte

@copyright:  2015 Equifax. All rights reserved.

@contact:    jason.decorte@equifax.com

Version History
 08/31/2005| Jason DeCorte   | Rotor is deprecated as of 2.3.  Implemented a new
           |                 | encryption algorithm called p3.  It was written by an
           |                 | authority on encryption and Python, found on the net.
 08/06/2007| Jason DeCorte   | Updated the default directories and added isdir check
 03/03/2014| Jason DeCorte   | Complete overhaul for Python 2.7 and new crypto package v5.0

5.1 jwd 4/7/2015
    Updated to only store if data_file_dir is provided and removed default value for data_file_dir
    Removed class attributes version and version date
    Added ability to use for encrypting/decrypting passwords without username
    Added clause to store value only if at least username is provided
    Updated string formatting and variable names
    Added generate key method
5.2 jwd 2/17/2016
    Added mode parameter to control whether the file is opened as read-only or read/write
5.3 jwd 7/19/2016
    Add generate_key method
    Added optional parameter to encrypt method so password could be passed in
    Replaced b64encode/b64decode with urlsafe versions
5.3.1 jwd3 7/20/2016
    Due to compatibility issues, created Password2 to do the url safe b64 encode/decode
    Password2 class is the start of re-engineering this class to separate encryption/decryption from storage
    Updated Password class to inherit from object
5.3.2 jwd3 09/12/2016
    Found an issue in decrypt when passwords exceeded 31 characters - changed to strip last 32 characters
    as key
"""
import os
import sys
import base64
import shelve
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

__all__ = ['Password']
__version__ = "5.3.2"
__date__ = '2003-08-31'
__updated__ = '2016-09-12'


class Password(object):
    """ This class is used to encrypt and decrypt passwords."""

    def __init__(self,host=None,username=None,password=None,data_file_name=None,data_file_dir=None,mode='r'):
        self.host = host
        self.username = username
        self.password = password
        self.error = False
        self.errmsg = None
        self.isOpen = False
        self.encrypted_pswd = None
        # name of file to store values
        if data_file_name:
            self.data_file_name = data_file_name
        else:
            self.data_file_name = ".pddatafile"
        self.data_file_dir = data_file_dir
        self.mode = 'c' if mode == 'w' else mode
        self.key_size = (SHA256.block_size * 3) / 8 + SHA256.digest_size

    def __del__(self):
        """ When destructed, close file"""
        if self.isOpen:
            self.__close_datafile()

    def set_hostname(self,host):
        self.host = host

    def set_username(self,username):
        self.username = username

    def set_password(self,password):
        self.password = password

    def set_data_file_dir(self,data_file_dir):
        self.data_file_dir = data_file_dir

    def set_data_file_name(self,data_file_name):
        self.data_file_name = data_file_name

    def get_password(self,enc_flag=False):
        if enc_flag:
            return self.encrypted_pswd
        else:
            return self.password

    def is_error(self):
        return self.error

    def get_error_message(self):
        return 'ERROR: ' + self.errmsg

    def __generate_key(self):
        """
        Private method: Generate a random key
        """
        return os.urandom(self.key_size)[:SHA256.digest_size]

    def __create_key(self):
        """
        Private method: Create the key from the username and host
        """
        md = SHA256.new()
        md.update(self.username)
        if self.host:
            md.update(self.host)
            md.update(self.host[::-1])
        md.update(self.username[::-1])
        return md.digest()  # create 32byte key

    def encrypt(self):
        """
        Encrypt the password
        :return:
        """
        if self.password is None:
            self.encrypted_pswd = None
            self.error = True
            self.errmsg = 'Missing password to encrypt'
        else:
            if self.username:
                key = self.__create_key()
            else:
                key = self.__generate_key()
            pad = AES.block_size - len(self.password) % AES.block_size
            data = self.password + chr(pad) * pad
            iv = os.urandom(AES.block_size)
            cipher = AES.new(key,AES.MODE_CBC,iv)
            self.encrypted_pswd = base64.b64encode(iv + cipher.encrypt(data) + key)
            self.error = False
            self.errmsg = None
            if self.data_file_dir and self.username:
                self.__store_record()
        return self.encrypted_pswd

    def decrypt(self,encrypted_password=None):
        """
        Decrypt a password
        :param encrypted_password:
        :return:
        """
        if encrypted_password is None:
            if self.username:
                self.__retrieve_record()
                encrypted_password = self.encrypted_pswd
            else:
                self.password = 'NF'
                self.error = True
                self.errmsg = 'Missing User Name'
        if not self.error:
            iv = base64.b64decode(encrypted_password)[:AES.block_size]
            key = base64.b64decode(encrypted_password)[-SHA256.digest_size:]
            data = base64.b64decode(encrypted_password)[AES.block_size:-SHA256.digest_size]
            cipher = AES.new(key,AES.MODE_CBC,iv)
            temp_pswd = cipher.decrypt(data)
            decrypted_pwd = temp_pswd[:-ord(temp_pswd[-1])]
            self.password = decrypted_pwd
            self.error = False
        return self.password

    def remove_record(self):
        """ Remove a record from the data file """
        if not self.isOpen:
            self.__open_datafile()
        if not self.error:
            if self.username:
                self.__create_db_key()
                if self.dbkey in self.datafile.keys():
                    del self.datafile[self.dbkey]
                else:
                    self.error = True
                    self.errmsg = 'Record NOT found.'
            else:
                self.error = True
                self.errmsg = "Missing required username."
            if self.isOpen:
                self.__close_datafile()

    def get_all(self):
        """ Return a list of all the records """
        if not self.isOpen:
            self.__open_datafile()
        if not self.error:
            key_list = self.datafile.keys()
            entry_list = []
            for key in key_list:
                entry_list.append(self.datafile[key])
            if self.isOpen:
                self.__close_datafile()
            return entry_list
        else:
            return []

    def __create_db_key(self):
        """ Create the database key for storing """
        if self.host and self.username:
            temp_key = self.username + '@' + self.host
        else:
            temp_key = self.username
        self.dbkey = SHA256.new(temp_key).hexdigest()
        return self.dbkey

    def __retrieve_record(self):
        """ Retrieve a record from the password database """
        if not self.isOpen:
            self.__open_datafile()
        if not self.error:
            if self.username:
                self.__create_db_key()
                if self.dbkey in self.datafile.keys():
                    self.record = self.datafile[self.dbkey]
                    self.dbname = self.record['host']
                    self.username = self.record['username']
                    self.encrypted_pswd = self.record['rsakey']
                    self.error = False
                else:
                    self.encrypted_pswd = ''
                    self.error = True
                    self.errmsg = 'Record does not exist'
                    self.record = None
            else:
                self.error = True
                self.errmsg = 'Missing username'
                self.record = None
            if self.isOpen:
                self.__close_datafile()

    def __store_record(self):
        """ Store the record in the database """
        self.record = {'host':self.host,'username':self.username,'rsakey':self.encrypted_pswd}
        if not self.isOpen:
            self.__open_datafile()
        if not self.error:
            self.__create_db_key()
            try:
                self.datafile[self.dbkey] = self.record
                self.error = False
                self.errmsg = None
            except:
                value = sys.exc_info()[1]
                self.error = False
                self.errmsg = 'Cannot write to data file - Error {0!s}'.format(value)
        if self.isOpen:
            self.__close_datafile()

    def __open_datafile(self):
        """ Open the password file """
        if os.path.isdir(self.data_file_dir):
            try:
                self.datafile = shelve.open(os.path.join(self.data_file_dir,self.data_file_name),flag=self.mode)
            except:
                self.isOpen = False
                self.error = True
                value = sys.exc_info()[1]
                self.errmsg = 'Cannot open data file - Error {0!s}'.format(value)
            else:
                self.isOpen = True
                self.error = False
                self.errmsg = None
        else:
            self.isOpen = False
            self.error = True
            if not os.path.isdir(self.data_file_dir):
                self.errmsg = 'Directory [%s] NOT found' % str(self.data_file_dir)
            elif not os.path.isfile(self.data_file_name):
                self.errmsg = 'File [{0!s}] NOT found in directory {1!s}'.format(self.data_file_name,self.data_file_dir)
            else:
                self.errmsg = 'Cannot open data file'

    def __close_datafile(self):
        """ explicitly close the data file """
        # data_file_dir and data_file_name have to be set or the file couldn't be open
        try:
            self.datafile.close()
        except:
            self.isOpen = False
            self.error = True
            value = sys.exc_info()[1]
            self.errmsg = 'Cannot close data file!\nError %s' % str(value)
        else:
            self.isOpen = False


class Password2(Password):
    """ This class is used to encrypt and decrypt passwords.
        This version uses urlsafe b64 encode and decode and other enhancements."""

    def __init__(self,host=None,username=None,password=None,data_file_name=None,data_file_dir=None,mode='r',key=None):
        super(Password2,self).__init__(host,username,password,data_file_name,data_file_dir,mode)
        if key:
            self.key = base64.urlsafe_b64decode(key)
        else:
            self.key = None

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, password=None):
        """
        Encrypt the password
        :param password: Password to encrypt
        :return:
        """
        plain_password = password or self.password
        if not plain_password:
            self.encrypted_pswd = None
            self.error = True
            self.errmsg = 'Missing password to encrypt'
        else:
            if self.key:
                key = self.key
            elif self.username:
                key = self.__create_key()
            else:
                key = self.__generate_key()
            pad = AES.block_size - len(plain_password) % AES.block_size
            data = plain_password + chr(pad) * pad
            iv = os.urandom(AES.block_size)
            cipher = AES.new(key,AES.MODE_CBC,iv)
            self.encrypted_pswd = base64.urlsafe_b64encode(iv + cipher.encrypt(data) + key)
            self.error = False
            self.errmsg = None
        return self.encrypted_pswd

    def save_to_file(self):
        """
        Save the data record to the file
        :return:
        """
        if self.data_file_dir and self.username:
            self.__store_record()

    def decrypt(self,encrypted_password=None):
        """
        Decrypt a password
        :param encrypted_password:
        :return:
        """
        if encrypted_password is None:
            self.password = None
            self.error = True
            self.errmsg = 'Missing encrypted password'
        else:
            iv = base64.urlsafe_b64decode(encrypted_password)[:AES.block_size]
            key = base64.urlsafe_b64decode(encrypted_password)[SHA256.digest_size:]
            data = base64.urlsafe_b64decode(encrypted_password)[AES.block_size:SHA256.digest_size]
            cipher = AES.new(key,AES.MODE_CBC,iv)
            temp_pswd = cipher.decrypt(data)
            decrypted_pwd = temp_pswd[:-ord(temp_pswd[-1])]
            self.password = decrypted_pwd
            self.error = False
        return self.password

    def get_record(self):
        """
        Get record from file
        :return:
        """
        if self.username:
            self.__retrieve_record()
        else:
            self.password = 'NF'
            self.error = True
            self.errmsg = 'Missing User Name'
