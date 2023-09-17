#!/bin/python3

# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    ft_otp.py                                          :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: sleleu <sleleu@student.42.fr>              +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2023/09/17 19:43:25 by sleleu            #+#    #+#              #
#    Updated: 2023/09/17 19:43:26 by sleleu           ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

import argparse
import time
from cryptography.fernet import Fernet
import hmac
import struct
import hashlib

# X represents the time step in seconds (default value X = 30 seconds) and is a system parameter.
X = 30
# T0 is the Unix time to start counting time steps  (default value is 0, i.e., the Unix epoch) and is also a system parameter.
T0 = 0
# T is an integer and represents the number of time steps between the initial counter time T0 and the current Unix time.
T = (int(time.time()) - T0) // X

def encrypt_key(K: str):
    fernet_key: bytes = Fernet.generate_key()
    cipher = Fernet(fernet_key) # Create fernet instance
    encrypted_key: bytes = cipher.encrypt(K.encode()) # encrypt K in cipher
    with open("ft_otp.key", "wb") as filekey:
        filekey.write(encrypted_key)

def generateTOTP(K: str, T: int):
    K_bytes = bytes.fromhex(K)
    msg = struct.pack(">Q", T) # encode in big endian 8 bytes
    hmac_result = hmac.new(K_bytes, msg, hashlib.sha1).digest() # calcul a HMAC hash with SHA-1
    selected_byte = hmac_result[19] & 15
    result = (struct.unpack(">I", hmac_result[selected_byte:selected_byte+4])[0] & 0x7fffffff) % 1000000
    otp_str = str(result)
    return (otp_str.zfill(6))

def parse_arguments():
    desc = "A simple TOTP (Time-based One-Time Password) system capable of generating ephemeral passwords from a master key."
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("-g", "--generate", nargs=1, help="receives as argument a hexadecimal key of at least 64 characters. The program stores this key safely in a file called ft_otp.key, which is encrypted.")
    parser.add_argument("-k", "--key", nargs=1, help="generates a new temporary password based on the key given as argument and prints it on the standard output.")
    return (parser.parse_args())

if __name__ == "__main__":
    args = parse_arguments()
    K = "17f019ff2069c3d054706b6348"
    if args.generate:
        encrypt_key(K)
    otp_code = generateTOTP(K, T)
    print(otp_code)