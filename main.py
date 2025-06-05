# Copyright (C) 2025 L1stak
#
# This file is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.


from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import string
import random
import hashlib

bit_sdvig = 4
IP = '1.1.271.1'
LENGTH_FOR_KEY = 64


def generate_id(length):
    characters = string.ascii_letters + string.digits  
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string
        
def generate_session_key(ip: str,user_password_hash):
    """Start session
    param:
    ip - server ip or a string that both server and client know about
    
    return bytes
    """
    
    identifier = generate_id(10)
    if  any(char.isdigit() for char in identifier[:3]):
        salt = ip.encode()  + generate_id(bit_sdvig)
        salt_hash = hashlib.sha256(salt).hexdigest().encode() # str
    else: 
        salt = ip.encode()
        salt_hash = hashlib.sha256(salt).hexdigest().encode()
        
    hashed_bytes = salt_hash
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=hashed_bytes, # bytes
    iterations=100000,
    backend=default_backend()
    )
    master_key = kdf.derive(ip.encode() + hashed_bytes + user_password_hash.encode()) # МОЖНО ЕЩЁ + identifier
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(user_password_hash[:16].encode()), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(os.urandom(LENGTH_FOR_KEY)) + encryptor.finalize()
    file = open('data/session' + str(identifier)+ '.sfmp','w+')
    file.write(str(identifier))
    file.close()
    
    return  encrypted_key, identifier

def get_session_key_and_check(ip,identifier,user_password_hash,chipered_key):
            if any(char.isdigit() for char in identifier[:3]):
                salt = ip.encode()  + generate_id(bit_sdvig)
                salt_hash = hashlib.sha256(salt).hexdigest().encode() # str
            else: 
                salt = ip.encode()
                salt_hash = hashlib.sha256(salt).hexdigest().encode()
        

            hashed_bytes = salt_hash
            kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashed_bytes, # bytes
            iterations=100000,
            backend=default_backend()
            )
            temp_key = kdf.derive(ip.encode() + hashed_bytes + user_password_hash.encode())
            
            cipher = Cipher(algorithms.AES(temp_key), modes.CBC(user_password_hash[:16].encode()), backend=default_backend())
            decryptor = cipher.decryptor()

            key = decryptor.update(chipered_key) + decryptor.finalize()
            
            return key
    
    

    
    
user_hash = hashlib.sha256(input('Введите пароль \n').encode()).hexdigest()
# Генерация случайного ключа AES
k, indifier = generate_session_key(IP,user_hash)
true_key = get_session_key_and_check(IP,indifier,user_hash,k)
print(f'encypted key: {k}, id: {indifier} , true_key = {true_key}')
