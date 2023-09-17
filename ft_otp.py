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

def HOTP(K: str, T: int):
    print(f"K: {K}")
    print(f"T: {T}")

def parse_arguments():
    desc = "A simple TOTP (Time-based One-Time Password) system capable of generating ephemeral passwords from a master key."
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("-g", "--generate", nargs=1, help="receives as argument a hexadecimal key of at least 64 characters. The program stores this key safely in a file called ft_otp.key, which is encrypted.")
    parser.add_argument("-k", "--key", nargs=1, help="generates a new temporary password based on the key given as argument and prints it on the standard output.")
    return (parser.parse_args())

if __name__ == "__main__":
    args = parse_arguments()
    K = "This is a key"
    if args.generate:
        encrypt_key(K)
    HOTP(K, T)