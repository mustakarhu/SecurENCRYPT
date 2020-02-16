import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
# from Crypto.Random import get_random_bytes
from Crypto import Random

CHKSIZE = 1024
BLOCKSIZE = 16
OUTFILEAPP = ".enc"


def encrypt(key, filename):
	chunksize = CHKSIZE #size of chunks read from the file
	outputfile = filename+OUTFILEAPP
	filesize = str(os.path.getsize(filename)).zfill(BLOCKSIZE) #zfill inserts zeroes padding
	IV = Random.new().read(BLOCKSIZE)

	encryptor = AES.new(key, AES.MODE_CBC, IV)
	with open(filename, 'rb') as infile:
		with open(outputfile, 'wb') as outfile:
			outfile.write(filesize.encode('utf-8'))
			outfile.write(IV)

			while True:
				chunk = infile.read(chunksize)
				if(len(chunk)==0):
					break
				elif(len(chunk)%BLOCKSIZE!=0):
					chunk+=b' '* (BLOCKSIZE-(len(chunk)%BLOCKSIZE))
				outfile.write(encryptor.encrypt(chunk))




def decrypt(key, filename):
	chunksize = CHKSIZE
	outputfile = filename[:-len(OUTFILEAPP)]

	with open(filename, 'rb') as infile:
		filesize = int(infile.read(BLOCKSIZE))
		IV = infile.read(BLOCKSIZE)

		decryptor = AES.new(key, AES.MODE_CBC, IV)
		with open(outputfile, 'wb') as outfile:

			while True:
				chunk = infile.read(chunksize)
				if len(chunk)==0 :
					break

				outfile.write(decryptor.decrypt(chunk))
			outfile.truncate(filesize)



def get_key(PWInput):
'''
input(s)
	password: name of the file to be used for digest generation. This file is effectively the password for the cipher
return value(s)
	hash digest: computed from password file input
'''
	Password=''.encode("utf-8")
	with open(PWInput, 'r') as PWFile:
		for Line in PWFile:
			Password+= Line.encode('utf-8')

	Hasher = SHA256.new(Password)

	return Hasher.digest()


def main():

	selection = input("Select e for encrypt or d for decrypt: ")
	if(selection.lower()=="e"):
		filename = input("Name of file to be encrypted: ")
		password = input("Name of the password file: ")
		encrypt(get_key(password),filename)

	elif(selection.lower()=="d"):
		filename = input("Name of file to be decrypted: ")
		password = input("Name of the password file: ")
		decrypt(get_key(password),filename)

	else:
		print("Invalid input please try again.")

if __name__ == '__main__':
	main()