/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   myCrypto.c

Written By: 
     1- Jessy Bradshaw
     2-
     
Submitted on: 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// LAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             uint8_t *key, uint8_t *iv, uint8_t *pCipherText )
{
	int status;
	unsigned len=0, encryptedLen=0;
	
	/* Create and initialise the context */
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if( ! ctx  )
		handleErrors("encrypt: failed to creat CTX");
	
	// Initialise the encryption operation
	status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv);
	if( status != 1 )
		handleErrors("encrypt: failed to EncryptInit_ex");
	
	// Call EncryptUpdate as many times as needed (e.g. inside a loop)
	// to perform regular encryption
	status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len);
	if(status != 1)
		handleErrors("encrypt: failed to EncryptUpdate");
	encryptedLen += len;
	
	// If additional ciphertext may still be generated,
	// the pCipherText pointer must be first advanced forward
	pCipherText += len;
	
	// Finalize the encryption.
	status = EVP_EncryptFinal_ex(ctx, pCipherText, &len);
	if( status != 1)
		handleErrors("encrypt: failed to EncryptFinal_ex");
	encryptedLen += len;  // len could be 0 if no additional cipher text was generated
	
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	
	return encryptedLen;
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                  uint8_t *key, uint8_t *iv, uint8_t *pDecryptedText)
{
	int status;
	unsigned len=0, decryptedLen=0;
	
	/* Create and initialise the context */
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx)
		handleErrors("decrypt: failed to creat CTX");
	
	// Initialise the decryption operation.
	status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
	if(status != 1)
		handleErrors("decrypt: failed to DecryptInit_ex");
	
	// Call DecryptUpdate as many times as needed (e.g. inside a loop)
	// to perform regular decryption
	status = EVP_DecryptUpdate(ctx, pDecryptedText, &len, pCipherText, cipherText_len);
	if( status != 1)
		handleErrors("decrypt: failed to DecryptUpdate");
	decryptedLen += len;
	
	// If additional decrypted text may still be generated,
	// the pDecryptedText pointer must be first advanced forward
	pDecryptedText += len;
	
	// Finalize the decryption.
	status = EVP_DecryptFinal_ex( ctx, pDecryptedText, &len);
	if(status != 1)
		handleErrors("decrypt: failed to DecryptFinal_ex");
	decryptedLen += len;
	
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	
	return decryptedLen;
}

//***********************************************************************
// PA-01
//***********************************************************************

int encryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
	int status;
	unsigned len=0, bytes=0, sumLen=0;
	unsigned char buffer[ PLAINTEXT_LEN_MAX ];
	
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx)
		handleErrors("encryptFile: failed to creat CTX");
	
	//  AES cipher in CBC mode with a 256-bit key.
	status = EVP_EncryptInit_ex( ctx, ALGORITHM(), NULL, key, iv);
	if( status != 1 )
		handleErrors("encryptFile: failed to EncryptInit_ex");

	while(1)
	{
		bytes = read(fd_in, buffer, sizeof(buffer));
		sumLen += bytes;
		if(bytes <= 0)
			break;
		
		status = EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, bytes);
		if( status -= 1)
			handleErrors("encryptFile: EVP_EncryptUpdate failed");
		write(fd_out, ciphertext, len);
	}
	
	status = EVP_EncryptFinal_ex(ctx, ciphertext, &len);
	if( status != 1)
		handleErrors("encryptFile: failed to EncryptFinal_ex");
	
	write(fd_out, ciphertext, len);
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	
	return sumLen;
}

//-----------------------------------------------------------------------------
int decryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
	int status;
	unsigned len=0, bytes=0, sumLen=0;
	unsigned char buffer[ CIPHER_LEN_MAX ];
	
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx)
		handleErrors("decryptFile: failed to creat CTX");
	
	//  AES cipher in CBC mode with a 256-bit key.
	status = EVP_DecryptInit_ex( ctx, ALGORITHM(), NULL, key, iv);
	if( status != 1 )
		handleErrors("decryptFile: failed to DecryptInit_ex");

	while(1)
	{
		bytes = read(fd_in, buffer, sizeof(buffer));
		sumLen += bytes;
		if(bytes <= 0)
			break;
		
		status = EVP_DecryptUpdate(ctx, plaintext, &len, buffer, bytes);
		if( status != 1)
			handleErrors("decryptFile: EVP_DecryptUpdate failed");
		write(fd_out, plaintext, len);
	}
	
	status = EVP_DecryptFinal_ex(ctx, plaintext, &len);
	if( status != 1)
		handleErrors("decryptFile: failed to DecryptFinal_ex");
	
	write(fd_out, plaintext, len);
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	
	return sumLen;
}

//***********************************************************************
// LAB-02
//***********************************************************************

RSA *getRSAfromFile(char * filename, int public)
{
    RSA * rsa;
    // open the binary file whose name is 'filename' for reading
	FILE * file = fopen(filename, "r");
    // Create a new RSA object using RSA_new() ;
	rsa = RSA_new();
	// if( public ) read a public RSA key into 'rsa'.  Use PEM_read_RSA_PUBKEY()
    // else read a private RSA key into 'rsa'. Use PEM_read_RSAPrivateKey()
	if(public)
	{
		rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
	}
	else
	{
		rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
	}
	// close the binary file 'filename'
	fclose(file);
    return rsa;
}

//***********************************************************************
// PA-02
//***********************************************************************

size_t fileDigest( int fd_in , int fd_out , uint8_t *digest )
// Read all the incoming data stream from 'fd_in' file descriptor
// Compute the SHA256 hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_out' is > 0, write a copy of the incoming data stream
// file to 'fd_out'
// Returns actual size in bytes of the computed hash (a.k.a. digest value)
{	
	unsigned int md_len;
	unsigned char buffer[ INPUT_CHUNK ];
	
	// Use EVP_MD_CTX_create() to create new hashing context
	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

    // Initialize the context using EVP_DigestInit() so that it deploys 
	// the EVP_sha256() hashing function 
	EVP_DigestInit(mdctx, EVP_sha256());

	/* Loop until end-of input file */
    while ( 1 )
    {
        // read( fd_in, ...  , INPUT_CHUNK );
		// read() returns bytes read
		if(read(fd_in, buffer, INPUT_CHUNK) == 0)
		{
			break;
		}

		// Use EVP_DigestUpdate() to hash the data you read
		EVP_DigestUpdate(mdctx, buffer, sizeof(buffer));
        if ( fd_out > 0 )
            // write the data you just read to fd_out
			write(fd_out, buffer, INPUT_CHUNK);
    }

    // Finialize the hash calculation using EVP_DigestFinal() directly
	// into the 'digest' array
	// digest size written into md_len
	EVP_DigestFinal(mdctx, digest, &md_len);

    // Use EVP_MD_CTX_destroy( ) to clean up the context
	EVP_MD_CTX_destroy(mdctx);

    // return the length of the computed digest in bytes ;
	return md_len;
}


