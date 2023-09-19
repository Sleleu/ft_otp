# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    ft_encryption.py                                   :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: sleleu <sleleu@student.42.fr>              +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2023/09/19 15:08:43 by sleleu            #+#    #+#              #
#    Updated: 2023/09/19 15:49:15 by sleleu           ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

import os
from cryptography.fernet import Fernet

def encrypt_key(K):
	fernet_key: bytes = Fernet.generate_key()
	cipher = Fernet(fernet_key) # Create fernet instance
	encrypted_key: bytes = cipher.encrypt(K.encode()) # encrypt K in cipher
	if os.path.exists("ft_otp.key"):
		print("./ft_opt.py: error: ft_otp.key file already exist. Please create key in another directory or delete key.")
		exit(1)
	if os.path.exists("master.key"):
		print("./ft_opt.py: error: master.key file already exist. Please create  master key in another directory or delete old master key.")
		exit(1)
	with open("ft_otp.key", "wb") as filekey:
		filekey.write(encrypted_key)
	print("Key was successfully saved in ft_otp.key.")
	with open("master.key", "wb") as masterkey:
		masterkey.write(fernet_key)
	print("Master key was successfully saved in master.key. Use this master key to read ft_otp.key and create TOTP password")

def decrypt_key(K: str, master_key: str):
	try:
		cipher = Fernet(master_key)
		decrypted_otp_key = cipher.decrypt(K)
	except:
		print("./ft_otp.py: error: invalid master key or otp key.")
		exit(1)
	return (decrypted_otp_key)