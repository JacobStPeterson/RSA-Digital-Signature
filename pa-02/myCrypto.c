/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   myCrypto.c

Written By: 
     1- Jacob Peterson (peter2js)
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
	// ....
	// Your previous code MUST be here
	// ....
	// Your code from pLab-01
    int status;
    unsigned len = 0, encryptedLen = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors ("Encrypt: failed tot create CTX");
    }

    // Initialise the encryption operation
    status = EVP_EncryptInit_ex (ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1) {
        handleErrors ("Encrypt: failed to EncryptInit_ex");
    }

    // call EncryptUpdate as many times as needed to perform
    // regular encryption
    status = EVP_EncryptUpdate (ctx, pCipherText, &len, 
            pPlainText, plainText_len);
    if (status != 1) {
        handleErrors ("Encrypt: failed to EncryptUpdate");
    }
    encryptedLen += len;

    // if additional ciphertext may still be generated,
    // the pchiphertext pointer must be first advanced forward
    pCipherText += len;

    // Finalize the encryption
    status = EVP_EncryptFinal_ex (ctx, pCipherText, &len);
    if (status != 1) {
        handleErrors ("Encrypt: failed to EncryptFinal_ex");
    }
    encryptedLen += len;

    EVP_CIPHER_CTX_free (ctx);

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
	// ....
	// Your previous code MUST be here
	// ....
	// Your code from pLab-01
    int status;
    unsigned len = 0, decryptedLen = 0;

    // create and intialise the context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors ("decrypt: failed to create CTX");
    }

    // Initialise the decryption operation
    status = EVP_DecryptInit_ex (ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1) {
        handleErrors ("decrypt: failed to DecryptInit_ex");
    }

    // call update to perform regular decryption
    status = EVP_DecryptUpdate (ctx, pDecryptedText, &len, pCipherText,
            cipherText_len);
    if (status != 1) {
        handleErrors ("decrypt: failed to DecryptUpdate");
    }

    decryptedLen += len;

    pDecryptedText += len;

    status = EVP_DecryptFinal_ex (ctx, pDecryptedText, &len);
    if (status != 1) {
        handleErrors ("decrypt: failed to DecryptFinal_ex");
    }
    decryptedLen += len;

    EVP_CIPHER_CTX_free (ctx);

    return decryptedLen;
}

//***********************************************************************
// PA-01
//***********************************************************************

int encryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
	// ....
	// Your previous code MUST be here
	// ....
	// initialize
    int status;
    unsigned len = 0;
    unsigned encrypt_len = 0;
    
    // initialize the context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) 
        handleErrors ("Encrypt: failed tot create CTX");

    // Initialise the encryption operation
    status = EVP_EncryptInit_ex (ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors ("Encrypt: failed to EncryptInit_ex");

    // loop over blocks of the plaintext, encrypt each one, send each block
    // to the data channel
    ssize_t cipher_len;
    while ((cipher_len = read (fd_in, plaintext, PLAINTEXT_LEN_MAX)) > 0) {

        // encrypt chunk that was read in
        status = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, cipher_len);
        if (status != 1) handleErrors("Encrypt: failed to EncryptUpdate");

        // increament the total size of the encrypted text
        encrypt_len += len;

        // send encrypted block to basim
        if (write (fd_out, ciphertext, len) != len)
            handleErrors ("Encrypt: failed to write correct amount of data");

    }
    // Finalize the encryption
    status = EVP_EncryptFinal_ex (ctx, ciphertext, &len);
    if (status != 1) handleErrors ("Encrypt: failed to EncryptFinal_ex");

    encrypt_len += len;

    // send the last of the encrypted text to basim
    write (fd_out, ciphertext, len);

    // free the context, dont want any memory leak
    EVP_CIPHER_CTX_free (ctx);

    return encrypt_len;
}

//-----------------------------------------------------------------------------
int decryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
	// ....
	// Your previous code MUST be here
	// ....
	// initialize
    int status;
    unsigned len = 0;
    unsigned decrypt_len = 0;

    // initialize the context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors ("Decrypt : Failed to create ctx");

    // initialize the decription operation
    status = EVP_DecryptInit_ex (ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1) handleErrors ("Decrypt : Failed to initiate decrypt");

    // loop over the blocks of encrypted text that were sent via the data channel
    // decrept each block, then write the new plaintext to fd_out
    ssize_t plain_len;
    while ((plain_len = read (fd_in, ciphertext, CIPHER_LEN_MAX)) > 0) {

        // decrypt the block
        status = EVP_DecryptUpdate (ctx, decryptext, &len, ciphertext, plain_len);
        if (status != 1) handleErrors ("Decrypt : failed to Decrypt Update");

        // increment the size of the decrypt file
        decrypt_len += len;

        // send the decrypted block to fd_out
        if (write (fd_out, decryptext, len) != len)
            handleErrors ("Decrypt : write length and decrypt text differ in length");
    }

    // finialize the decyprtion
    status = EVP_DecryptFinal_ex (ctx, decryptext, &len);
    if (status != 1)
        handleErrors ("Decrypt : failed to Finalize");

    // send the last bit of decyrpted text to fd_out
    if (write (fd_out, decryptext, len) != len)
        handleErrors ("Decrypt : failed to write final block");
    
    // free the context
    EVP_CIPHER_CTX_free (ctx);

    return decrypt_len;
}

//***********************************************************************
// LAB-02
//***********************************************************************

RSA *getRSAfromFile(char * filename, int public)
{
	// ....
	// Your previous code MUST be here
	// ....
	RSA * rsa;
    // open the binary file whose name is 'filename' for reading
    FILE *fp = fopen (filename, "rb");
    if (fp == NULL) handleErrors ("getRSA : Failed to open file");

    // Create a new RSA object using RSA_new() ;
    rsa = RSA_new();

    // if( public ) read a public RSA key into 'rsa'.  Use PEM_read_RSA_PUBKEY()
    if (public) 
    {
        rsa = PEM_read_RSA_PUBKEY (fp, &rsa, NULL, NULL);
    } 
    // else read a private RSA key into 'rsa'. Use PEM_read_RSAPrivateKey()
    else 
    {
        rsa = PEM_read_RSAPrivateKey (fp, &rsa, NULL, NULL);
    }

    // close the binary file 'filename'
    fclose (fp);

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
	// Use EVP_MD_CTX_create() to create new hashing context

    // Initialize the context using EVP_DigestInit() so that it deploys 
	// the EVP_sha256() hashing function 

    while ( /* Loop until end-of input file */ )
    {
        // read( fd_in, ...  , INPUT_CHUNK );

		// Use EVP_DigestUpdate() to hash the data you read

        if ( fd_out > 0 )
            // write the data you just read to fd_out
			printf ("lmao");
    }

    // Finialize the hash calculation using EVP_DigestFinal() directly
	// into the 'digest' array

    // Use EVP_MD_CTX_destroy( ) to clean up the context

    // return the length of the computed digest in bytes ;
}


