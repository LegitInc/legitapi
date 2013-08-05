# Copyright (C) 2013  Rob Boyle / Legit Inc
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses

# IMPORTANT - Mirrored aviators should be worn at ALL TIMES when working
# with this module. A leather jacket and 3-day stubble are left to the discretion
# of the individual, but are highly recommended.

import os
import hashlib
import hmac
import base64
from Crypto.Cipher import AES
from Crypto import Random

# global crypto values
SALT = None
AES_KEY = None
PUBLIC_SALT = None

# Hack to tell if we're running in development or production
if os.environ.get('SERVER_SOFTWARE','').startswith('Development'):
    DEVELOPMENT = True
    SALT = "dev_salt"
    AES_KEY = hashlib.sha256("dev_key").digest()
else:
    DEVELOPMENT = False

def get_random_bytes(num_bytes):
    if DEVELOPMENT:
        return os.urandom(num_bytes)
                
    return Random.get_random_bytes(num_bytes)

def _get_salt():
    global SALT
    if not SALT:
        with open("legit.salt", "rb") as saltfile:
            SALT = saltfile.read()
            
    return SALT
    
def _get_aes_key():
    global AES_KEY
    if not AES_KEY:
        with open("legit.key", "rb") as keyfile:
            AES_KEY = keyfile.read()
    
    return AES_KEY
    
def _get_public_salt():
    global PUBLIC_SALT
    if not PUBLIC_SALT:
        with open("public.salt", "r") as public_saltfile:
            PUBLIC_SALT = public_saltfile.read()
            
    return PUBLIC_SALT


def _string_or_bust(value):
    """
    Converts the given value to a string suitable for encryption/hashing.
    All values are encoded as utf-8 strings (which is the same as ascii for 
    everything except strings with non-ascii unicdoe characters)
    """
    if isinstance(value, unicode):
        value = value.encode('utf-8')
    else:
        value = str(value)
        
    return value


def _hash_value(value, salt):
    """
    De-identifies a value by one-way hashing it, using the provided salt.
    """
    value = _string_or_bust(value)
            
    return hmac.new(salt, msg=value, digestmod=hashlib.sha256).hexdigest()

def public_hash_value(value, salt=None):
    """
    De-identifies a value using the salt and hashing strategy that we
    release to our customers, so they can hash the data before it gets to us.
    """
    if not salt:
        salt = _get_public_salt()
    
    return _hash_value(value, salt=salt)


def hash_value(value, salt=None, pre_hashed=False):
    """
    De-identifies a value by one-way hashing it, for storage in our database.
    
    To be compatible with people who pre-hash data for us, if it hasn't been
    done already, we first hash the data using our public hash algo/salt. The
    data is then hashed again for storage/queries, using our internal, secret
    salt.  
    """
    if not pre_hashed:
        value = public_hash_value(value)

    if not salt:
        salt = _get_salt()        
    
    return _hash_value(value, salt)


def encrypt_value(value, aes_key=None):  
    """Encrypts a value so it can be decrypted later.
        
        Args:
            value: The plaintext value to be encrypted.                    
        Returns:
            A base64 encoded version of the value suitable for storage.
    """
    if not aes_key:
        aes_key = _get_aes_key()
    
    value = _string_or_bust(value)
    iv = get_random_bytes(AES.block_size)
    aes_encrypt = AES.new(aes_key, AES.MODE_CFB, iv)
    ciphertext = iv + aes_encrypt.encrypt(value)
    
    return base64.b64encode(ciphertext)
    
    
def decrypt_value(encrypted_value, aes_key=None):
    """Decrypts the given value using the provided private key
    
    Args:
        encrypted_value: pickled tuple of encrypted data
        private_key: PEM format private RSA key
    Returns:
        plaintext version of the value
    """
    if not aes_key:
        aes_key = _get_aes_key()
        
    encrypted_value = base64.b64decode(encrypted_value)
    iv = encrypted_value[:AES.block_size]
    encrypted_value = encrypted_value[AES.block_size:]
    aes_decrypt = AES.new(aes_key, AES.MODE_CFB, iv)
    
    return aes_decrypt.decrypt(encrypted_value)
    
    
    
    
    
    
    