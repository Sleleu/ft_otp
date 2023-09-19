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

import argparse, time, datetime
import hmac, struct, hashlib
from ft_encryption import encrypt_key, decrypt_key

TIME = int(time.time())

# X represents the time step in seconds (default value X = 30 seconds) and is a system parameter.
X = 30
# T0 is the Unix time to start counting time steps  (default value is 0, i.e., the Unix epoch) and is also a system parameter.
T0 = 0
# T is an integer and represents the number of time steps between the initial counter time T0 and the current Unix time.
T = (TIME - T0) // X

LIGHT_CYAN = "\033[1;36m"
END = "\033[0m"

ascii_header = """

███████╗████████╗      ██████╗ ████████╗██████╗ 
██╔════╝╚══██╔══╝     ██╔═══██╗╚══██╔══╝██╔══██╗
█████╗     ██║        ██║   ██║   ██║   ██████╔╝
██╔══╝     ██║        ██║   ██║   ██║   ██╔═══╝ 
██║        ██║███████╗╚██████╔╝   ██║   ██║     
╚═╝        ╚═╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝     
			Created by : https://github.com/Sleleu
"""

def generateTOTP(K: str, T: int, digits: int):
	K_bytes = bytes.fromhex(K)
	msg = struct.pack(">Q", T) # encode in big endian 8 bytes

	DIGITS_POWER = [1,10,100,1000,10000,100000,1000000,10000000,100000000]
    #  0 1  2   3    4     5      6       7        8

	hash = hmac.new(K_bytes, msg, hashlib.sha1).digest()
	offset = hash[-1] & 0xf

	binary = ((hash[offset] & 0x7f) << 24)     | \
			 ((hash[offset + 1] & 0xff) << 16) | \
			 ((hash[offset + 2] & 0xff) << 8)  | \
			 (hash[offset + 3] & 0xff)
	otp = binary % DIGITS_POWER[digits]				
	otp_str = str(otp)
	return (otp_str.zfill(digits))

def parse_arguments():
	desc = "A simple TOTP (Time-based One-Time Password) system capable of generating ephemeral passwords from a master key."
	parser = argparse.ArgumentParser(description=desc)
	parser.add_argument("-g", "--generate", nargs=1, help="receives as argument a hexadecimal key of at least 64 characters. The program stores this key safely in a file called ft_otp.key, which is encrypted.")
	parser.add_argument("-k", "--key", nargs=1, help="generates a new temporary password based on the key given as argument and prints it on the standard output.")
	parser.add_argument("-m", "--master", nargs=1, help="use this master key to read ft_otp.key and create TOTP password")
	parser.add_argument("-d", "--digits", default=6, type=int, choices=range(4, 9), help="select the number of digits (between 1 and 8) for the TOTP password. 6 digits by default")
	parser.add_argument("-v", "--verbose", action="store_true", help="show verbose output")
	return (parser.parse_args())

def getKeyFromArg(g_arg):
	try:
		with open(g_arg, "r") as file:
			K = file.read()
	except FileNotFoundError:
		K = g_arg
	try:
		assert len(K) >= 64
		bytes.fromhex(K)
	except AssertionError or ValueError:
		print("./ft_otp: error: key must be 64 hexadecimal characters")
		exit(1)
	return (K)

def displayVerboseOutput(hexa: bytes, digits: int, T: int):
	date = datetime.datetime.utcnow()
	month = str(date.month).zfill(2)
	day = str(date.day).zfill(2)
	print(f"Hex secret: {bytes.decode(hexa)}")
	print(f"Digits: {digits}")
	print(f"TOTP mode: SHA1")
	print(f"Step size (seconds): {X}")
	print(f"Start time: 1970-01-01 00:00:00 UTC ({T0})")
	print(f"Current time: {date.year}-{month}-{day}", end="")
	print(f" {str(date.hour).zfill(2)}:{str(date.minute).zfill(2)}:{str(date.second).zfill(2)}", end="")
	print(f" UTC ({TIME})")
	print(f"Counter: {hex(T).upper()} ({T})\n")

if __name__ == "__main__":
	print(f"{LIGHT_CYAN}{ascii_header}{END}")
	args = parse_arguments()
	if args.generate:
		K = getKeyFromArg(args.generate[0])
		encrypt_key(K)
	elif args.key:
		if args.master is None:
			print("usage: argument '-m', '--master' MASTER_KEY is required to decrypt ft_opt.key")
			exit(1)
		try:
			with open(args.key[0]) as file:
				otp_key = file.read()
			with open(args.master[0]) as file:
				master_key = file.read()
		except FileNotFoundError as Error:
			print(f"./ft_otp.py: error: {Error.filename} does not exist.")
			exit(1)
		decrypted_otp_key = decrypt_key(otp_key.encode(), master_key.encode())
		otp_code = generateTOTP(decrypted_otp_key.decode(), T, args.digits)
		if args.verbose is True:
			displayVerboseOutput(decrypted_otp_key, args.digits, T)
		print(otp_code)
