/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c    SKELETON

Written By: 
     1- Jessy Bradshaw
     2- Jacob Peterson

Submitted on: 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "\n%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    exit(-1);
}

//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

// For the following Encryption/Decryption, 
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             const uint8_t *key, const uint8_t *iv, uint8_t *pCipherText )
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
                  const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
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

static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext[ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application
//-----------------------------------------------------------------------------

int encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{

}

//***********************************************************************
// pLAB-02
//***********************************************************************

RSA *getRSAfromFile(char * filename, int public)
{
    FILE * fp = fopen(filename,"rb");
    if (fp == NULL)
    {
        fprintf( stderr , "getRSAfromFile: Unable to open RSA key file %s \n",filename);
        return NULL;    
    }

    RSA *rsa = RSA_new() ;
    if ( public )
        rsa = PEM_read_RSA_PUBKEY( fp, &rsa , NULL , NULL );
    else
        rsa = PEM_read_RSAPrivateKey( fp , &rsa , NULL , NULL );
 
    fclose( fp );

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
// Returns actual size in bytes of the computed digest
{

}



//***********************************************************************
// PA-04  Part ONE
//***********************************************************************

void exitError( char *errText )
{
    fprintf( stderr , "%s\n" , errText ) ;
    exit(-1) ;
}


//-----------------------------------------------------------------------------
// Utility to read Key/IV from files
// Return:  1 on success, or 0 on failure

int getMasterKeyFromFiles( char *keyF , char *ivF , myKey_t *x )
{
    int   fd_key , fd_iv ;
    
    fd_key = open( keyF , O_RDONLY )  ;
    if( fd_key == -1 ) 
    { 
        fprintf( stderr , "\nCould not open key file '%s'\n" , keyF ); 
        return 0 ; 
    }
    read ( fd_key , x->key , SYMMETRIC_KEY_LEN ) ;
    close( fd_key ) ;

    fd_iv = open( ivF , O_RDONLY )  ;
    if( fd_iv == -1 ) 
    { 
        fprintf( stderr , "\nCould not open IV file '%s'\n" , ivF ); 
        return 0 ; 
    }
    read ( fd_iv , x->iv , INITVECTOR_LEN ) ;
    close( fd_iv ) ;
    
    return 1;  //  success
}

//-----------------------------------------------------------------------------
// Build a new Message #2 from the KDC to Amal
// Where Msg2 before encryption:  L(Ks) || Ks || L(IDb) || IDb  || L(Na) || Na || L(TktCipher) || TktCipher
// All Len(*) fields are unsigned integers
// Set *msg2 to point at the newly built message
// Log milestone steps to the 'log' file for debugging purposes
// Returns the size (in bytes) of the encrypted (using Ka) Message #2  

unsigned MSG2_new( FILE *log , uint8_t **msg2, const myKey_t *Ka , const myKey_t *Kb , 
                   const myKey_t *Ks , const char *IDa , const char *IDb  , Nonce_t *Na )
{

    if (log == NULL || msg2 == NULL || Ka == NULL || Kb == NULL || 
         Ks == NULL || IDa == NULL || IDb == NULL || Na == NULL)
    {
        fprintf( log , "NULL pointer(s) passed to MSG2_new() ... EXITING\n"  );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "NULL pointer(s) passed to MSG2_new()" );
    }

    unsigned LenA   = strlen( IDa ) + 1 ;
    unsigned LenB   = strlen( IDb ) + 1 ;

    // Construct TktPlain = { Ks  || L(IDa)  || IDa }
    // in a dynamically-allocated buffer
    unsigned tktPlainLen =  KEYSIZE + LENSIZE +  LenA ;

    if ( tktPlainLen > PLAINTEXT_LEN_MAX  )  
    {
        fprintf( log , "Plaintext of Ticket in MSG2_new is too big %u bytes( max is %u ) "
                       " ... EXITING\n" , tktPlainLen , PLAINTEXT_LEN_MAX );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nPlaintext of Ticket in MSG2_new is too big\n" );
    }

    uint8_t *TktPlain = malloc( tktPlainLen ) ;
    if ( !TktPlain )  
    {
        // similar to above, but with  "Out of Memory allocating for TktPlain in MSG2_new" 
        printf ("myCrypto : Out of Memory allocating for TktPlain in MSG2_new");
    }



    // 'p' is a temp pointer used to access segments of the TktPlain buffer
    uint8_t  *p = TktPlain ;      
    memcpy( p , Ks , KEYSIZE ) ;                        p += KEYSIZE ;

    unsigned *lenPtr ;    
    lenPtr = (unsigned *) p  ;   *lenPtr = LenA ;       p += LENSIZE ;
    memcpy( p , IDa , LenA );




    fprintf( log ,"    Plaintext Ticket (%u Bytes) is\n" , tktPlainLen);
    BIO_dump_indent_fp ( log , TktPlain , tktPlainLen , 4 ) ;  fprintf( log , "\n") ; 


    // Now, set TktCipher = encrypt( Kb , TktPlain );
    uint8_t *bCipherText = malloc (CIPHER_LEN_MAX);
    unsigned lenTktCipher = encrypt(TktPlain, tktPlainLen, Kb->key, Kb->iv, bCipherText) ;
    free( TktPlain ) ; // no longer needed

    // Construct the rest of Message 2 then encrypt it using Ka
    // MSG2 plain = {  Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher }
    
    // compute the legth of plaintext of MSG2 ;
    unsigned lenMsg2Plain =  KEYSIZE + LENSIZE + LenB + NONCELEN + LENSIZE + lenTktCipher;

    if ( lenMsg2Plain > PLAINTEXT_LEN_MAX  )  
    {
        fprintf( log , "Plaintext of MSG2 too big %u bytes( max is %u ) to encrypt in MSG2_new "
                       " ... EXITING\n" , lenMsg2Plain , PLAINTEXT_LEN_MAX );        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nPlaintext of MSG2 is too big in MSG2_new\n" );
    }

    uint8_t *platext = (uint8_t *) malloc(lenMsg2Plain);
    // Fill in Msg2 Plaintext:  Ks || L(IDb) || IDb  || Na || lenTktCipher) || TktCipher

    // Reuse the moving pointer 'p' , but now to contsruct plaintext of MSG2
    fprintf( log ,"This is the new MSG2 ( %u Bytes ) before Encryption:\n" , lenMsg2Plain);



    p = platext;

    // Ks
    memcpy (p, Ks, KEYSIZE);

    fprintf( log ,"    Ks { key + IV } (%lu Bytes) is:\n" , KEYSIZE );
    BIO_dump_indent_fp ( log , p , KEYSIZE , 4 ) ;  fprintf( log , "\n") ; 

    p += KEYSIZE;

    //  L(IDb) || IDb
    lenPtr = (unsigned *) p ;   *lenPtr = LenB ;     p += LENSIZE ; 
    memcpy (p, IDb, LenB);

    fprintf( log ,"    IDb (%u Bytes) is:\n" , LenB );
    BIO_dump_indent_fp ( log , p , LenB , 4 ) ;  fprintf( log , "\n") ; 

    p += LenB;

    //  Na 
    memcpy (p, Na, NONCELEN);  

    fprintf( log ,"    Na (%lu Bytes) is:\n" , NONCELEN );
    BIO_dump_indent_fp ( log , p , NONCELEN , 4 ) ;  fprintf( log , "\n") ; 

    p += NONCELEN;

    //  L(TktCipher) || TktChipher 
    lenPtr = (unsigned *) p ;   *lenPtr = lenTktCipher;    p += LENSIZE ;
    memcpy (p, bCipherText, lenTktCipher);




    fprintf( log ,"    Encrypted Ticket (%u Bytes) is\n" , lenTktCipher );
    BIO_dump_indent_fp ( log , p , lenTktCipher , 4 ) ;  fprintf( log , "\n") ;

    // Now, encrypt Message 2 using Ka
    uint8_t *ciphertext = (uint8_t * ) malloc (CIPHER_LEN_MAX);
    unsigned LenMsg2 = encrypt( platext , lenMsg2Plain, Ka->key, Ka->iv, ciphertext);

    *msg2 = malloc( LenMsg2 ) ;
    if( *msg2 == NULL ) 
    {
        fprintf( log , "Out of Memory allocating %u bytes for MSG2 Ciphertext"
                       " in MSG2_new ... EXITING\n" , LenMsg2 );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nOut of Memory allocating for Ciphertext of MSG2 in MSG2_new\n" );
    }

    // Copy the encrypted ciphertext to Caller's msg2 buffer.
    memcpy( *msg2 , ciphertext , LenMsg2 ) ;

    fprintf( log , "The following new Encrypted MSG2 ( %u bytes ) has been"
                   " created by MSG2_new():  \n" , LenMsg2 ) ;
    BIO_dump_indent_fp( log , *msg2 , LenMsg2 , 4 ) ;    fprintf( log , "\n" ) ;    
    fflush( log ) ;    
    
    return LenMsg2 ;    
}

//-----------------------------------------------------------------------------
// Receive Message #2 by Amal from by the KDC
// Parse the incoming msg2 into the component fields 
// *Ks, *IDb, *Na and TktCipher = Encr{ L(Ks) || Ks  || L(IDa)  || IDa }

void MSG2_receive( FILE *log , int fd , const myKey_t *Ka , myKey_t *Ks, char **IDb , 
                       Nonce_t *Na , unsigned *lenTktCipher , uint8_t **tktCipher )
{
    // Here, using static arrays to avoid slow performance of malloc()
    unsigned  msg2CipherLen ;    
    unsigned *lenPtr ;    
    unsigned  LenB  ; 
    uint8_t *ciphtext;  

    if ( log == NULL || Ka == NULL || Ks == NULL || IDb == NULL || 
         Na == NULL || lenTktCipher == NULL || tktCipher == NULL )  
    {
        fprintf( log , "NULL pointer(s) passed to  MSG2_receive() ... EXITING\n"  );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "NULL pointer(s) passed to MSG2_receive()" );
    }

    // Read Len(Message 2)
    if (read( fd , &msg2CipherLen, LENSIZE  ) != LENSIZE )
    {
        fprintf( log , "Unable to read all %lu bytes of Len(MSG2) from FD %d in "
                       "MSG2_receive() ... EXITING\n" , LENSIZE , fd );
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    }

    if ( msg2CipherLen > CIPHER_LEN_MAX )  
    {
        fprintf( log , "Encrypted MSG2 is too big %u bytes( max is %u ) in MSG2_receive() "
                       " ... EXITING\n" , msg2CipherLen , CIPHER_LEN_MAX );
        
        fflush( log ) ;  fclose( log ) ;     
        exitError( "Encrypted MSG2 is too big in MSG2_receive()" );
    }

    // Now read MSG2 itself
    ciphtext = malloc (CIPHER_LEN_MAX);
    if ( read(fd, ciphtext, msg2CipherLen) != msg2CipherLen )  
    {
        fprintf( log , "Unable to read all %u bytes of encrypted MSG2 from FD %d in MSG2_receive() "
                       "... EXITING\n" , msg2CipherLen , fd ) ;
        fflush( log ) ;  fclose( log ) ;     
        exitError( "Unable to read all bytes of encrypted MSG2 in MSG2_receive()" );
    }

    fprintf( log ,"The following Encrypted MSG2 ( %u bytes ) has been received from FD %d Successfully\n" 
                 , msg2CipherLen , fd );
    BIO_dump_indent_fp( log , ciphtext , msg2CipherLen , 4 ) ;   fprintf( log , "\n");
    fflush( log ) ;

    // Decrypt  MSG2 using Ka
    unsigned msg2Len ;
    uint8_t *plaintext = malloc (PLAINTEXT_LEN_MAX);
    msg2Len = decrypt(ciphtext, msg2CipherLen, Ka->key, Ka->iv, plaintext) ;
    if (  msg2Len > DECRYPTED_LEN_MAX )  
    {
        fprintf( log , "Dercypted text of MSG2 is too big %u bytes( max is %u ) in MSG2_receive()"
                       " ... EXITING\n" , msg2Len , DECRYPTED_LEN_MAX ) ;
        fflush( log ) ;  fclose( log ) ;     
        exitError( "\nPlaintext too big decrypting received Msg2\n" );
    }

    // Parse the Decrypted Msg2 into its components: 
    // {  Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher }
    uint8_t *p = plaintext ;

    // Parse Ks & copy it to Caller's buffer
    memcpy( Ks , p , KEYSIZE )  ;                                 p += KEYSIZE ;  

   
    // Parse IDb & copy it to Caller's buffer
    lenPtr = (unsigned *) p    ;   LenB  = *lenPtr    ;         p += LENSIZE ;

    // Allocate LenB bytes for  *IDb  then copy form IDb to *IDb
    char *tmp = malloc (LenB);
    memcpy (tmp, p, LenB);                                      p += LenB; 
    *IDb = tmp;

    
    // Parse Na & copy it to Caller's buffer
    memcpy (Na , p, NONCELEN);                                 p += NONCELEN; 

    // Allocate exact memory to Caller's   *tktCipher
    // Parse the Encrypted Ticket & copy it to Caller's buffer
    lenPtr = (unsigned *) p    ;   LenB  = *lenPtr    ;         p += LENSIZE ;
    *lenTktCipher = LenB;
    tmp = malloc (LenB);
    memcpy (tmp, p, LenB);                              
    *tktCipher = tmp;
    
    return ;
}

