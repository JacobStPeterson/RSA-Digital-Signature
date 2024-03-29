/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.h

              D O    N O T    M O D I F Y     T H I S    F I L E
Written By: 
     1- Mohamed Aboutabl

----------------------------------------------------------------------------*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <linux/random.h>
#include <assert.h>

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

// For symmetric-key Encryption/Decryption, 
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm
#define ALGORITHM          EVP_aes_256_cbc
#define SYMMETRIC_KEY_LEN  32
#define INITVECTOR_LEN     16

//***********************************************************************
// pLAB-01
//***********************************************************************

#define CIPHER_LEN_MAX     2048
#define PLAINTEXT_LEN_MAX (CIPHER_LEN_MAX - 32)
#define DECRYPTED_LEN_MAX (CIPHER_LEN_MAX)


void       handleErrors( char *msg ) ;

unsigned   encrypt( uint8_t *pPlainText, unsigned plainText_len, 
                    const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText ) ;

unsigned   decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                    const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText) ;

//***********************************************************************
// PA-01
//***********************************************************************

int    encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv );
int    decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv );

//***********************************************************************
// pLAB-02
//***********************************************************************

RSA    *getRSAfromFile(char * filename, int public) ;

//***********************************************************************
// PA-02
//***********************************************************************

size_t fileDigest( int fd_in , int fd_out , uint8_t *digest ) ;


//***********************************************************************
// PA-04   Part  ONE
//***********************************************************************

typedef  uint32_t         Nonce_t[ 1 ] ; 

// Key Object = symmetricKey || IV in one structure for easier argument passing
typedef struct {
            uint8_t  key[ SYMMETRIC_KEY_LEN ] , 
                     iv [ INITVECTOR_LEN ] ;
        }  myKey_t ; 

#define NONCELEN       ( sizeof(Nonce_t)  )
#define LENSIZE        ( sizeof(unsigned) )
#define KEYSIZE        ( sizeof( myKey_t  ) )

void     exitError( char *errText ) ;
int      getMasterKeyFromFiles( char *keyF , char *ivF , myKey_t *x ) ;

unsigned MSG2_new( FILE * log , uint8_t **msg2 , const myKey_t *Ka , const myKey_t *Kb , 
                   const myKey_t *Ks , const char *IDa , const char *IDb , Nonce_t *Na ) ;

void     MSG2_receive( FILE *log , int fd , const myKey_t *Ka , myKey_t *Ks, char **IDb , 
                       Nonce_t *Na , unsigned *lenTktCipher , uint8_t **tktCipher ) ;

