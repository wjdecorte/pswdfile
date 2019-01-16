"""
  Name: password.py

  Purpose: This class is contains methods to encrypt and decrypt passwords per
           database and username combination.
  !!!!WARNING!!!! This class is not secure enough for any type of highly sensitive data
                  and is only met for use on casual applications to keep passwords from
                  being stored in ASCII plain text format.  Implement with AES128 for
                  complete security.

@author:     Jason DeCorte

@copyright:  2015 DeCorte Industries.com. All rights reserved.

@contact:    jdecorte@decorteindustries.com

Version History
 08/31/2005| Jason DeCorte   | Rotor is deprecated as of 2.3.  Implemented a new
           |                 | encryption algorithm called p3.  It was written by an
           |                 | authority on encryption and Python, found on the net.
 08/06/2007| Jason DeCorte   | Updated the default directories and added isdir check
 03/03/2014| Jason DeCorte   | Complete overhaul for Python 2.7 and new crypto package v5.0

0.04 jwd3 4/7/2015
    Updated to only store if data_file_dir is provided and removed default value for data_file_dir
    Removed class attributes version and version date
    Added ability to use for encrypting/decrypting passwords without username
    Added clause to store value only if at least username is provided
    Updated string formatting and variable names
    Added generate key method
0.05 jwd3 2/17/2016
    Added mode parameter to control whether the file is opened as read-only or read/write
0.06 jwd3 7/19/2016
    Add generate_key method
    Added optional parameter to encrypt method so password could be passed in
    Replaced b64encode/b64decode with urlsafe versions
0.07 jwd3 7/20/2016
    Due to compatibility issues, created Password2 to do the url safe b64 encode/decode
    Password2 class is the start of re-engineering this class to separate encryption/decryption from storage
    Updated Password class to inherit from object
0.08 jwd3 09/12/2016
    Found an issue in decrypt when passwords exceeded 31 characters - changed to strip last 32 characters
    as key
0.09 jwd3 03/15/2017
    Added property decorator and changed attributes to be private
0.10 jwd3 05/17/2017
    Removed print statement
    Code cleanup
    Changed version to 0.xx where xx is a sequential number - major/minor/revision format not needed
"""
import os
import sys
import base64
import cPickle
import shelve
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

__all__ = ['Password']
__version__ = "0.10"
__date__ = '2003-08-31'
__updated__ = '05/17/2017'


class Password(object):
    """ This class is used to encrypt and decrypt passwords."""

    def __init__(self,host=None,username=None,password=None,data_file_name=None,data_file_dir=None,mode='r'):
        self._host = host
        self._username = username
        self._password = password
        self.error = False
        self.errmsg = None
        self.isOpen = False
        self._encrypted_pswd = None
        self.return_encrypted = False  # flag to determine which version of password to return
        # name of file to store values
        if data_file_name:
            self._data_file_name = data_file_name
        else:
            self._data_file_name = ".pddatafile"
        self._data_file_dir = data_file_dir
        self.mode = 'c' if mode == 'w' else mode
        self.key_size = (SHA256.block_size * 3) / 8 + SHA256.digest_size

    def __del__(self):
        """ When destructed, close file"""
        if self.isOpen:
            self.__close_datafile()

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self,value):
        self._host = value

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self,value):
        self._username = value

    @property
    def data_file_dir(self):
        return self._data_file_dir

    @data_file_dir.setter
    def data_file_dir(self,value):
        self._data_file_dir = value

    @property
    def data_file_name(self):
        return self._data_file_name

    @data_file_name.setter
    def data_file_name(self,value):
        self._data_file_name = value

    @property
    def password(self):
        if self.return_encrypted:
            return self._encrypted_pswd
        else:
            return self._password

    @password.setter
    def password(self,value):
        self._password = value

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
        md.update(self._username)
        if self._host:
            md.update(self._host)
            md.update(self._host[::-1])
        md.update(self._username[::-1])
        return md.digest()  # create 32byte key

    def encrypt(self):
        """
        Encrypt the password
        :return:
        """
        if self._password is None:
            self._encrypted_pswd = None
            self.error = True
            self.errmsg = 'Missing password to encrypt'
        else:
            if self._username:
                key = self.__create_key()
            else:
                key = self.__generate_key()
            pad = AES.block_size - len(self._password) % AES.block_size
            data = self._password + chr(pad) * pad
            iv = os.urandom(AES.block_size)
            cipher = AES.new(key,AES.MODE_CBC,iv)
            self._encrypted_pswd = base64.b64encode(iv + cipher.encrypt(data) + key)
            self.error = False
            self.errmsg = None
            if self._data_file_dir and self._username:
                self.__store_record()
        return self._encrypted_pswd

    def decrypt(self,encrypted_password=None):
        """
        Decrypt a password
        :param encrypted_password:
        :return:
        """
        if encrypted_password is None:
            if self._username:
                self.__retrieve_record()
                encrypted_password = self._encrypted_pswd
            else:
                self._password = 'NF'
                self.error = True
                self.errmsg = 'Missing User Name'
        if not self.error:
            iv = base64.b64decode(encrypted_password)[:AES.block_size]
            key = base64.b64decode(encrypted_password)[-SHA256.digest_size:]
            data = base64.b64decode(encrypted_password)[AES.block_size:-SHA256.digest_size]
            cipher = AES.new(key,AES.MODE_CBC,iv)
            temp_pswd = cipher.decrypt(data)
            decrypted_pwd = temp_pswd[:-ord(temp_pswd[-1])]
            self._password = decrypted_pwd
            self.error = False
        return self._password

    def remove_record(self):
        """ Remove a record from the data file """
        if not self.isOpen:
            self.__open_datafile()
        if not self.error:
            if self._username:
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
                if isinstance(self.datafile[key],str):
                    rec = cPickle.loads(base64.b64decode(self.datafile[key]))
                else:
                    rec = self.datafile[key]
                entry_list.append(rec)
            if self.isOpen:
                self.__close_datafile()
            return entry_list
        else:
            return []

    def __create_db_key(self):
        """ Create the database key for storing """
        if self._host and self._username:
            temp_key = self._username + '@' + self._host
        else:
            temp_key = self._username
        self.dbkey = SHA256.new(temp_key).hexdigest()
        return self.dbkey

    def __retrieve_record(self):
        """ Retrieve a record from the password database """
        if not self.isOpen:
            self.__open_datafile()
        if not self.error:
            if self._username:
                self.__create_db_key()
                if self.dbkey in self.datafile.keys():
                    record = self.datafile[self.dbkey]
                    if isinstance(record,str):
                        self.record = cPickle.loads(base64.b64decode(record))
                    else:
                        self.record = record
                    self._host = self.record['host']
                    self._username = self.record['username']
                    self._encrypted_pswd = self.record['rsakey']
                    self.error = False
                else:
                    self._encrypted_pswd = ''
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
        self.record = {'host':self._host,'username':self._username,'rsakey':self._encrypted_pswd}
        if not self.isOpen:
            self.__open_datafile()
        if not self.error:
            self.__create_db_key()
            try:
                self.datafile[self.dbkey] = base64.b64encode(cPickle.dumps(self.record))
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
        if os.path.isdir(self._data_file_dir):
            try:
                self.datafile = shelve.open(os.path.join(self._data_file_dir,self._data_file_name),flag=self.mode)
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
            if not os.path.isdir(self._data_file_dir):
                self.errmsg = 'Directory [%s] NOT found' % str(self._data_file_dir)
            elif not os.path.isfile(self._data_file_name):
                self.errmsg = 'File [{0!s}] NOT found in directory {1!s}'.format(self._data_file_name,
                                                                                 self._data_file_dir)
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
        plain_password = password or self._password
        if not plain_password:
            self._encrypted_pswd = None
            self.error = True
            self.errmsg = 'Missing password to encrypt'
        else:
            if self.key:
                key = self.key
            elif self._username:
                key = self.__create_key()
            else:
                key = self.__generate_key()
            pad = AES.block_size - len(plain_password) % AES.block_size
            data = plain_password + chr(pad) * pad
            iv = os.urandom(AES.block_size)
            cipher = AES.new(key,AES.MODE_CBC,iv)
            self._encrypted_pswd = base64.urlsafe_b64encode(iv + cipher.encrypt(data) + key)
            self.error = False
            self.errmsg = None
        return self._encrypted_pswd

    def save_to_file(self):
        """
        Save the data record to the file
        :return:
        """
        if self._data_file_dir and self._username:
            self.__store_record()

    def decrypt(self,encrypted_password=None):
        """
        Decrypt a password
        :param encrypted_password:
        :return:
        """
        if encrypted_password is None:
            self._password = None
            self.error = True
            self.errmsg = 'Missing encrypted password'
        else:
            iv = base64.urlsafe_b64decode(encrypted_password)[:AES.block_size]
            key = base64.urlsafe_b64decode(encrypted_password)[SHA256.digest_size:]
            data = base64.urlsafe_b64decode(encrypted_password)[AES.block_size:SHA256.digest_size]
            cipher = AES.new(key,AES.MODE_CBC,iv)
            temp_pswd = cipher.decrypt(data)
            decrypted_pwd = temp_pswd[:-ord(temp_pswd[-1])]
            self._password = decrypted_pwd
            self.error = False
        return self._password

    def get_record(self):
        """
        Get record from file
        :return:
        """
        if self._username:
            self.__retrieve_record()
        else:
            self._password = 'NF'
            self.error = True
            self.errmsg = 'Missing User Name'
