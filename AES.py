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



def getKey(password):
	hasher = SHA256.new(password.encode('utf-8'))
	return hasher.digest()


def main():

	func = input("function e, d: ")
	if(func=="e"):
		filename = input("Name of file to be encrypted: ")
		password = input("Password: ")
		encrypt(getKey(password),filename)
	elif(func=="d"):
		filename = input("Name of file to be decrypted: ")
		password = input("Password: ")
		decrypt(getKey(password),filename)

if __name__ == '__main__':
	main()