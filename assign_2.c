#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);



/* TODO Declare your function prototypes here... */



/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{
    //char *salt = "12340000";
    int ic = 1;

	if(bit_mode == 128)
	{	
		EVP_BytesToKey(EVP_aes_128_ecb(), EVP_sha1(), NULL, (unsigned char*)password, strlen((char*)password), ic, key, NULL);
		printf("KEY IS: \n");
		print_hex(key, 16);
	}
	else if(bit_mode == 256)
	{
		EVP_BytesToKey(EVP_aes_256_ecb(), EVP_sha1(), NULL, (unsigned char*)password, strlen((char*)password), ic, key, NULL);
    	printf("KEY IS: \n");
		print_hex(key, 32);
	}

	

}


/*
 * Encrypts the data
 */
void
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{

	/* TODO Task B */
	int len;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (bit_mode==128) 
		EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
	else if (bit_mode==256) 
		EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);

	EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

	EVP_CIPHER_CTX_free(ctx);

	return;

}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	int plaintext_len;

	plaintext_len = 0;

	/*TODO Task C */
	EVP_CIPHER_CTX *ctx;

    int len = 0;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();
    

	if(bit_mode == 128)
		EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv);
	else if(bit_mode == 256)
		EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv);
    
	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{

	/* TODO Task D */
	size_t len;
	CMAC_CTX *ctx = CMAC_CTX_new();

	if (bit_mode==128) 
		CMAC_Init(ctx, key, 16, EVP_aes_128_ecb(), NULL);
	else if (bit_mode==256) 
		CMAC_Init(ctx, key, 32, EVP_aes_256_ecb(), NULL);

	CMAC_Update(ctx, data, data_len);

	CMAC_Final(ctx, cmac, &len);

	CMAC_CTX_free(ctx);
	
	return;


}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	int verify;

	verify = 0;


	/* TODO Task E */
	if(strcmp((char*)cmac1,(char*)cmac2)==0)
	{
    	printf("Input cmac was verified!\n" );
    	return 1;
	}
	else{
		printf("Failed to verify input cmac\n" );
		return 0;
	}

	return verify;
}



/* TODO Develop your functions here... */



/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */
	

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;

	


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);



	/* TODO Develop the logic of your tool here... */




	/* Initialize the library */
	unsigned char *key;
	unsigned char *iv;
	unsigned char *cmac1;//Buffer for cmac
  	unsigned char *cmac2;//Buffer for verification of cmac

	size_t outSize;
	FILE *inFile = fopen(input_file,"r");   //Declare the inputFile in reading mode
 	FILE *outFile = fopen(output_file, "w");//Declare the outputFile in writing mode
	
	size_t pos = ftell(inFile);    // Current position
	fseek(inFile, 0, SEEK_END);    // Go to end
	size_t fileLength = ftell(inFile); // read the position which is the size
	fseek(inFile, pos, SEEK_SET);  // restore original position

	outSize = (fileLength/BLOCK_SIZE + 1)*BLOCK_SIZE;
    /*allocate memmory for the input buffer */
    unsigned char *inputFileMemory = (unsigned char*)malloc(sizeof(unsigned char*)*(int)fileLength);
	unsigned char *outputFileMemory = (unsigned char*)malloc(sizeof(unsigned char*)*(int)outSize);
	

	if (!fread(inputFileMemory,1,fileLength,inFile)) {
    	printf("Error passing file in memmory\n");
  	}
  	

	if(bit_mode == 128)
	{
		key = (unsigned char*)malloc(16*sizeof*key);
		cmac1 = (unsigned char*)malloc(sizeof(unsigned char*)*16);//Buffer for cmac
		cmac2 = (unsigned char*)malloc(sizeof(unsigned char*)*16);//Buffer for verification of cmac	
		
	}
	else if(bit_mode == 256)
	{
		key = (unsigned char*)malloc(32*sizeof*key);
		cmac1 = (unsigned char*)malloc(sizeof(unsigned char*)*32);//Buffer for cmac
		cmac2 = (unsigned char*)malloc(sizeof(unsigned char*)*32);//Buffer for verification of cmac
	}
	


	/* Keygen from password */
	keygen(password, key, iv, bit_mode);

	/* Operate on the data according to the mode */
	/* encrypt */
	switch (op_mode) {
  	case 0:
		encrypt(inputFileMemory, (int)fileLength, key, iv, outputFileMemory, bit_mode);
		fwrite(outputFileMemory, sizeof(char), outSize, outFile); 
		printf("ENCRYPTED HEX: \n");
		print_hex(outputFileMemory, outSize);
		printf("\nENCRYPTED IN FILE: %s",output_file);
		break;

	/* decrypt */
	case 1:
		outSize = decrypt(inputFileMemory, (int)fileLength, key, iv, outputFileMemory, bit_mode);
		fwrite(outputFileMemory, sizeof(char), outSize, outFile);
		printf("\nDECRYPTED TO FILE: %s \n",output_file);
		break;

	/* sign */
	case 2:
		/* encrypt */
		encrypt(inputFileMemory, (int)fileLength, key, iv, outputFileMemory, bit_mode);
		printf("ENCRYPTED HEX:\n");
		print_hex(outputFileMemory,outSize);
		/* generate cmac */
		gen_cmac(inputFileMemory, fileLength, key, cmac1, bit_mode);
		printf("CMAC: \n");
		if (bit_mode == 128)
		{
			print_hex(cmac1,16);
		}
		else if(bit_mode == 256)
		{
			print_hex(cmac1,16);
		}
		
		/* sign */
		fwrite(outputFileMemory, sizeof(char), outSize, outFile);
		fwrite(cmac1, sizeof(char), 16, outFile);
		break;

	/* verify */
	case 3:
		fileLength -=16;
		memcpy(cmac1, &inputFileMemory[fileLength], 16);
		printf("CMAC IS: \n");
		print_hex(cmac1, 16);
		outSize = decrypt(inputFileMemory, fileLength, key, iv, outputFileMemory, bit_mode);
		gen_cmac(outputFileMemory, outSize, key, cmac2, bit_mode);\
		if(bit_mode == 256)
			memcpy(cmac2, &cmac2[16], 0);
		
		printf("NEW CMAC: \n");
		print_hex(cmac2,16);
		/* verify */
		if (verify_cmac(cmac2,cmac1))
		{
			fwrite(outputFileMemory, sizeof(char), outSize, outFile);
			printf("FILE %s HAS BEEN CREATED / CHANGED\n", output_file);
		}
		break;
	}
	/* Clean up */
	fclose(inFile);
  	fclose(outFile);
	free(input_file);
	free(key);
	free(outputFileMemory);
	free(inputFileMemory);
	free(cmac1);
	free(cmac2);
	free(output_file);
	free(password);


	/* END */
	return 0;
}
