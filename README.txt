Dimitrios Eleftheriadis 2015030067

To build the executable of the assignment, please first run "make all assign_2", if "assign_2" doesn't already exist.

The folder contains:
	-assign_2.c
	This file contains all of the implementation for the given assignment.

	-Makefile
	This file is used to build the executable. I have changed it in order to avoid any confusion, because it initially had as Target 	"assign_1", but our given file was assign_2.c.

	-Multiple .txt files.
	These are the text files that were used for the assignment. Each one of them is self-explanatory.


TASKS:

Task 1: 

	Task 1 was run with the following command; "./assign_2 -i encryptme_256.txt -o decryptme_256.txt -p TUC2015030067 -b 256 -e", which
	got the "encryptme_256.txt" file as an input and using the cipher aes-128-ecb, produced "decryptme_256.txt", an encrypted file, as output.

Task 2:

	Task 2 was run with the following command; "./assign_2 -i hpy414_decryptme_128.txt -o hpy414_encryptme_128.txt -b 128 -p hpy414 -d",
	which got the "hpy414_decryptme_128.txt" encrypted file as an input and using the cipher aes-128-ecb, produced "hpy414_encryptme_128.txt",
	a decrypted file, as the output.

Task 3:

	Task 3 was run with the following command; "./assign_2 -i signme_128.txt -o verifyme_128.txt -b 128 -p TUC2015030067 -s", which got
	the "signme_128.txt" text file as the input, then encrypted it using aes-128-ecb as the cipher, then generated a 16 byte long cmac 
	using the same cipher and concatenated the plaintext from the input file and the cmac, to a new file called "verifyme_128.txt".

Task 4:

	Task 4 was run with the following command; "./assign_2 -i hpy414_verifyme_128.txt -o verified_128.txt -b 128 -p hpy414 -v" and with
	"./assign_2 -i hpy414_verifyme_256.txt -o test.txt -b 256 -p hpy414 -v". They both got as input the plaintext concatenated with a cmac,
	then split the two apart, and then generated a new cmac and compared the two cmacs. Both of the commands failed to verify the given
	cmac.


	
