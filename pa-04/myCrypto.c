/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c         SKELETON  

Written By: 
     1-  Jacob Peterson
     2-  Jessy Bradshaw
Submitted on: 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
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

}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                  const uint8_t *key, const uint8_t *iv, uint8_t *pDecryptedText)
{

}

//***********************************************************************
// PA-01
//***********************************************************************

static unsigned char   plaintext  [ PLAINTEXT_LEN_MAX ] , // Temporarily store plaintext
                       ciphertext [ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       ciphertext2[ CIPHER_LEN_MAX    ] , // Temporarily store outcome of encryption
                       decryptext [ DECRYPTED_LEN_MAX ] ; // Temporarily store decrypted text

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application
//-----------------------------------------------------------------------------

int encryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{

}

//-----------------------------------------------------------------------------

int decryptFile( int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv )
{

}

//***********************************************************************
// pLAB-02
//***********************************************************************

RSA *getRSAfromFile(char * filename, int public)
{

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
// PA-04  Part  One
//***********************************************************************

void exitError( char *errText )
{
    fprintf( stderr , "%s\n" , errText ) ;
    exit(-1) ;
}

//-----------------------------------------------------------------------------
// Build a new Message #2 from the KDC to Amal
// Where Msg2 before encryption:  Ks || L(IDb) || IDb  || Na || L(TktCipher) || TktCipher
// All L() fields are unsigned integers
// Set *msg2 to point at the newly built message
// Log milestone steps to the 'log' file for debugging purposes
// Returns the size (in bytes) of the encrypted (using Ka) Message #2  

unsigned MSG2_new( FILE *log , uint8_t **msg2, const myKey_t *Ka , const myKey_t *Kb , 
                   const myKey_t *Ks , const char *IDa , const char *IDb  , Nonce_t *Na )
{
    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG2 New\n");
    fprintf( log , "**************************\n\n");

    //
    // Your code from PA-04 Part ONE
    //

    // Error Checking
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

    // Fill in Msg2 Plaintext:  Ks || L(IDb) || IDb  || Na || lenTktCipher) || TktCipher
    uint8_t *platext = (uint8_t *) malloc(lenMsg2Plain);
    p = platext;

    // Ks
    memcpy (p, Ks, KEYSIZE);                         p += KEYSIZE;

    //  L(IDb) || IDb
    lenPtr = (unsigned *) p ;   *lenPtr = LenB ;     p += LENSIZE ; 
    memcpy (p, IDb, LenB);                           p += LenB;

    //  Na 
    memcpy (p, Na, NONCELEN);                        p += NONCELEN;

    //  L(TktCipher) || TktChipher 
    lenPtr = (unsigned *) p ;   *lenPtr = lenTktCipher;   p += LENSIZE ;
    memcpy (p, bCipherText, lenTktCipher);

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

    fprintf( log ,"This is the new MSG2 ( %u Bytes ) before Encryption:\n" , lenMsg2Plain);  
    fprintf( log ,"    Ks { key + IV } (%lu Bytes) is:\n" , KEYSIZE );
    BIO_dump_indent_fp ( log , (uCharPtr) Ks , KEYSIZE , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    IDb (%u Bytes) is:\n" , LenB);
    BIO_dump_indent_fp ( log , (uCharPtr) IDb , LenB , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Na (%lu Bytes) is:\n" , NONCELEN);
    BIO_dump_indent_fp ( log , (uCharPtr) Na , NONCELEN , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log ,"    Encrypted Ticket (%u Bytes) is\n" , lenTktCipher);
    BIO_dump_indent_fp ( log , (uCharPtr) ciphertext , lenTktCipher , 4 ) ;  fprintf( log , "\n") ; 

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
    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG2 Receive\n");
    fprintf( log , "**************************\n\n");
    //
    // Your code from PA-04 Part ONE
    //

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
    return;
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

    fd_iv = open(ivF , O_RDONLY )  ;
    if( fd_iv == -1 ) 
    { 
        fprintf( stderr , "\nCould not open IV file '%s'\n" , ivF ); 
        return 0 ; 
    }
    read ( fd_iv , x->iv , INITVECTOR_LEN ) ;
    close( fd_iv ) ;
    
    return 1;  //  success
}


//***********************************************************************
// PA-04  Part  Two
//***********************************************************************

//-----------------------------------------------------------------------------
// Allocate & Build a new Message #1 from Amal to the KDC 
// Where Msg1 is:  Len(A)  ||  A  ||  Len(B)  ||  B  ||  Na
// All Len(*) fields are unsigned integers
// Set *msg1 to point at the newly built message
// Msg1 is not encrypted
// Returns the size (in bytes) of Message #1 

unsigned MSG1_new ( FILE *log , uint8_t **msg1 , const char *IDa , const char *IDb , const Nonce_t *Na )
{
    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG1 New\n");
    fprintf( log , "**************************\n\n");

    if (log == NULL || msg1 == NULL || IDa == NULL || IDb == NULL
            || Na == NULL) {
        fprintf( log , "NULL pointer(s) passed to  MSG1_new() ... EXITING\n"  );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "NULL pointer(s) passed to MSG1_new()" );
    }

    unsigned  LenA    = strlen( IDa ) + 1 ;
    unsigned  LenB    = strlen( IDb ) + 1 ;
    unsigned  LenMsg1 = LENSIZE + LenA + LENSIZE + LenB + NONCELEN ;
    unsigned *lenPtr ; 
    uint8_t  *p ;

    // Allocate memory for msg1. MUST always check malloc() did not fail
    msg1 = malloc (LenMsg1) ;
    if (!msg1)
        printf ("myCrypto : Out of Memory allocating for msg1 in MSG1_new") ;

    // Fill in Msg1:  Len( IDa )  ||  IDa   ||  Len( IDb )  ||  IDb   ||  Na
    p = *msg1;

    // Len(IDa) || IDa
    lenPtr = (unsigned *) p ;   *lenPtr = LenA ;     p += LENSIZE ; 
    memcpy (p, IDb, LenA);                           p += LenA;

    // Len(IDb) || IDb
    lenPtr = (unsigned *) p ;   *lenPtr = LenB ;     p += LENSIZE ; 
    memcpy (p, IDb, LenB);                           p += LenB;
    
    // Na
    memcpy (p, Na, NONCELEN);                        p += NONCELEN;   

    fprintf( log , "The following new MSG1 ( %u bytes ) has been created by MSG1_new ():\n" , LenMsg1 ) ;
    BIO_dump_indent_fp( log , *msg1 , LenMsg1 , 4 ) ;    fprintf( log , "\n" ) ;
    
    return LenMsg1 ;
}

//-----------------------------------------------------------------------------
// Receive Message #1 by the KDC from Amal
// Parse the incoming msg1 into the values IDa, IDb, and Na

void  MSG1_receive( FILE *log , int fd , char **IDa , char **IDb , Nonce_t *Na )
{
    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG1 Receive\n");
    fprintf( log , "**************************\n\n");

    if (log == NULL || IDa == NULL || IDb == NULL || Na == NULL) {
        fprintf( log , "NULL pointer(s) passed to  MSG1_recieve() ... EXITING\n"  );       
        fflush( log ) ;  fclose( log ) ;     
        exitError( "NULL pointer(s) passed to MSG1_recieve()" );
    }


    unsigned LenMsg1 , LenA , LenB ;
    uint8_t *msg1 ;

    // Read Len(Message 1)  
    if (read( fd , &LenMsg1, LENSIZE  ) != LENSIZE )
    {
        fprintf( log , "Unable to read all %lu bytes of Len(MSG2) from FD %d in "
                       "MSG2_receive() ... EXITING\n" , LENSIZE , fd );
        fflush( log ) ;  fclose( log ) ;    
        exitError( "" );
    }

    if (LenMsg1 > PLAINTEXT_LEN_MAX) {
        fprintf( log , "MSG1 is too big %u bytes( max is %u ) in MSG1_receive() "
                       " ... EXITING\n" , LenMsg1 , PLAINTEXT_LEN_MAX );
        fflush( log ) ;  fclose( log ) ;     
        exitError( "Encrypted MSG1 is too big in MSG1_receive()" );
    }
   
    // read in msg1
    msg1 = malloc (PLAINTEXT_LEN_MAX);
    if ( read(fd, msg1, LenMsg1) != LenMsg1 )  
    {
        fprintf( log , "Unable to read all %u bytes of MSG1 from FD %d in MSG1_receive() "
                       "... EXITING\n" , LenMsg1 , fd ) ;
        fflush( log ) ;  fclose( log ) ;     
        exitError( "Unable to read all bytes of MSG1 in MSG1_receive()" );
    }

    uint8_t *p = plaintext ;
    unsigned *lenPtr ;

    // Read in the components of Msg1:  L(A)  ||  A   ||  L(B)  ||  B   ||  Na
    // 1) Read Len(IDa)
    lenPtr = (unsigned *) p   ;    LenA = *lenPtr    ;          p += LENSIZE ;


    // 2) Allocate memory for, and Read IDa
    char *tmp = malloc (LenA) ;
    memcpy (tmp, p, LenA) ;                                     p += LenA ; 
    *IDa = tmp ;

    // 3) Read Len(IDb)
    lenPtr = (unsigned *) p   ;    LenB = * lenPtr   ;          p += LENSIZE ;


    // 4) Allocate memory for, and Read IDb
    tmp = malloc (LenB) ;
    memcpy (tmp, p, LenB) ;                                     p += LenB ;
    *IDb = tmp ;      

    // 5) Read Na
    memcpy (Na , p, NONCELEN);                                  p += NONCELEN;


    fprintf( log , "MSG1 ( %u bytes ) has been received"
                   " on FD %d by MSG1_receive():\n" ,  LenMsg1 , fd  ) ;   
    fflush( log ) ;

    return ;
}

//-----------------------------------------------------------------------------
// Build a new Message #3 from Amal to Basim
// MSG3 = {  L(TktCipher)  || TktCipher  ||  Na2  }
// No further encryption is done on MSG3
// Returns the size of Message #3  in bytes

unsigned MSG3_new( FILE *log , uint8_t **msg3 , const unsigned lenTktCipher , const uint8_t *tktCipher,  
                   const Nonce_t *Na2 )
{
    unsigned LenMsg3 ;
    uint8_t  *p ;    
    unsigned *lenPtr ;    

    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG3 New\n");
    fprintf( log , "**************************\n\n");
    //
    // .....  Missing Code
    //

    LenMsg3 = /* ... */ 
    ;
    // Allocate memory for msg3. MUST always check malloc() did not fail
    //
    // .....  Missing Code
    //


    p = *msg3 ;    
    // Set lenTktCipher  and  tktCipher  components of Msg3

    //
    // .....  Missing Code
    //

    
    // Set the Na component of MSG3
    // Set lenTktCipher  and  tktCipher  components of Msg3
    // Set the Na component of MSG3 
    //
    // .....  Missing Code
    //

    fprintf( log , "The following new MSG3 ( %u bytes ) has been created by "
                   "MSG3_new ():\n" , LenMsg3 ) ;
    //
    // .....  Missing Code
    //

    fflush( log ) ;    

    return( LenMsg3 ) ;
}

//-----------------------------------------------------------------------------
// Receive Message #3 by Basim from Amal
// Parse the incoming msg3 into its components Ks , IDa , and Na2
// The buffers for Kb, Ks, and Na2 are pre-created by the caller
// The value of Kb is set by the caller
// The buffer for IDA is to be allocated here into *IDa

void MSG3_receive( FILE *log , int fd , const myKey_t *Kb , myKey_t *Ks , char **IDa , Nonce_t *Na2 )
{
    uint8_t  *tktCipher ;     
    unsigned  lenTktCipher , lenTktPlain ;
    unsigned *lenPtr , LenA , LenMsg3;    

    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG3 Receive\n");
    fprintf( log , "**************************\n\n");
    //
    // .....  Missing Code
    //

    // Read Len(Message 3)  
    //
    // .....  Missing Code
    //

    // I) Read 1st part of MSG#3: The TicketCiphertext
    // into the global scratch buffer ciphertext[]. Make sure it fits
    //
    // .....  Missing Code
    //
    fprintf( log ,"The following Encrypted TktCipher ( %d bytes ) was received "
                  "via FD %d by MSG3_receive()\n" , lenTktCipher , fd );
    //
    // .....  Missing Code
    //


    fprintf( log ,"The following Encrypted TktCipher ( %d bytes ) was received "
                  "via FD %d by MSG3_receive()\n" , lenTktCipher , fd );
    //
    // .....  Missing Code
    //

    // I.1) Decrypt the ticket into the global scratch buffer decryptext[]. Make sure it fits
    //
    // .....  Missing Code
    //

    fprintf( log ,"Here is the Decrypted Ticket ( %d bytes ) in MSG3_receive():\n" , lenTktPlain ) ;
    //
    // .....  Missing Code
    //

    // Start parsing the Ticket into the Caller-provided arguments
    uint8_t  *p = decryptext ;

    // I.2) Parse the session key Ks and copy it to caller's buffer
    //
    // .....  Missing Code
    //

    // I.3) Parse IDA    
    //     I.3.1) Allocate buffer for the caller to hold IDA
    //     I.3.2)  Copy IDA to caller's buffer
    //
    // .....  Missing Code
    //

    // II) Finally, read the last part of MSG3: Na2
    //
    // .....  Missing Code
    //

    return ;
}

//-----------------------------------------------------------------------------
// Build a new Message #4 from Basim to Amal
// MSG4 = Encrypt( Ks ,  { fNa2 ||  Nb }   )
// A new buffer for *msg4 is allocated here
// All other arguments have been initialized by caller

// Returns the size of Message #4 after being encrypted by Ks in bytes

unsigned MSG4_new( FILE *log , uint8_t **msg4, const myKey_t *Ks , Nonce_t *fNa2 , Nonce_t *Nb )
{
    uint8_t  *p ;    
    unsigned *lenPtr ;

    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG4 New\n");
    fprintf( log , "**************************\n\n");
    //
    // .....  Missing Code
    //

    // Construct MSG4 Plaintext = { f(Na2)  ||  Nb }
    // Use the global scratch buffer plaintext[] for MSG4 plaintext and fill it in with component values
    //
    // .....  Missing Code
    //

 
    // Now, encrypt MSG4 plaintext using the session key Ks;
    // Use the global scratch buffer ciphertext[] to collect the result.  Make sure it fits.
    //
    // .....  Missing Code
    //

    // Now allocate a buffer for the caller, and copy the encrypted MSG4 to it
    *msg4 = malloc( /* .... */  ) ;
    //
    // .....  Missing Code
    //

    fprintf( log , "The following new Encrypted MSG4 ( %u bytes ) has been"
                   " created by MSG4_new ():  \n" , LenMsg4 ) ;
    //
    // .....  Missing Code
    //

    fflush( log ) ;    

    return LenMsg4 ;
    
}

//-----------------------------------------------------------------------------
// Receive Message #4 by Amal from Basim
// Parse the incoming encrypted msg4 into the values rcvd_fNa2 and Nb

void  MSG4_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *rcvd_fNa2 , Nonce_t *Nb )
{
    // MSG4 = Encr( Ks ,  { f(Na2) || Nb }  ) by Basim

    uint8_t  *p ;    
    unsigned  LenMsg4 , LenMSG4cipher  ;

    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG4 Receive\n");
    fprintf( log , "**************************\n\n");

    // Read Len( Msg4 ) followed by reading Msg4 itself
    // Always make sure read() and write() succeed    
    // Use the global scratch buffer ciphertext[] to receive MSG4. Make sure it fits. 
    //
    // .....  Missing Code
    //

    fprintf( log ,"\nThe following Encrypted MSG4 ( %u bytes ) was received"
                  " from FD %d :\n" , LenMSG4cipher , fd );
    //
    // .....  Missing Code
    //

    // Now, Decrypt MSG4 using Ks
    // Use the global scratch buffer decryptext[] to collect the results of decryption.
    // Make sure it fits.
    //
    // .....  Missing Code
    //


    // Parse MSG4 into its components f( Na2 ) and Nb
    //
    // .....  Missing Code
    //

    return ;
}

//-----------------------------------------------------------------------------
// Build a new Message #5 from Amal to Basim
// A new buffer for *msg5 is allocated here
// MSG5 = Encr( Ks  ,  { fNb }  )
// All other arguments have been initialized by caller
// Returns the size of Message #5  in bytes

unsigned MSG5_new( FILE *log , uint8_t **msg5, const myKey_t *Ks ,  Nonce_t *fNb )
{
    uint8_t  *p ;
    unsigned msg5PlainLen ;
    
    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG5 New\n");
    fprintf( log , "**************************\n\n");

    // Construct MSG5 Plaintext  = {  f(Nb)  }
    // Use the global scratch buffer plaintext[] for MSG5 plaintext. Make sure it fits 
    //
    // .....  Missing Code
    //

    // Now, encrypt( Ks , {plaintext} );
    // Use the global scratch buffer ciphertext[] to collect result. Make sure it fits.
    //
    // .....  Missing Code
    //

    // Now allocate a buffer for the caller, and copy the encrypted MSG5 to it
    //
    // .....  Missing Code
    //
 
    fprintf( log , "The following new Encrypted MSG5 ( %u bytes ) has been"
                   " created by MSG5_new ():  \n" , LenMSG5cipher ) ;
    //
    // .....  Missing Code
    //

    fflush( log ) ;    

    return LenMSG5cipher ;
    
}

//-----------------------------------------------------------------------------
// Receive Message 5 by Basim from Amal
// Parse the incoming msg5 into the value fNb

void  MSG5_receive( FILE *log , int fd , const myKey_t *Ks , Nonce_t *fNb )
{
    uint8_t  *p ;    
    unsigned  LenMsg5 , LenMSG5cipher , *lenPtr , LenNonce ;

    fprintf( log , "\n**************************\n");
    fprintf( log , "         MSG5 Receive\n");
    fprintf( log , "**************************\n\n");

    // Read Len( Msg5 ) followed by reading Msg5 itself
    // Always make sure read() and write() succeed
    //
    // .....  Missing Code
    //

    // Use the global scratch buffer ciphertext[] to receive encrypted MSG5.
    // Make sure it fits.
    //
    // .....  Missing Code
    //


    fprintf( log ,"The following Encrypted MSG5 ( %u bytes ) has been received"
                  " from FD %d :\n" , LenMSG5cipher , fd );
    //
    // .....  Missing Code
    //


    // Now, Decrypt MSG5 using Ks
    // Use the global scratch buffer decryptext[] to collect the results of decryption
    // Make sure it fits
    //
    // .....  Missing Code
    //


    // Parse MSG5 into its components f( Nb )
    //
    // .....  Missing Code
    //

    return ;
}

//-----------------------------------------------------------------------------
// Utility to compute r = F( n ) for Nonce_t objects
// For our purposes, F( n ) = ( n + 1 ) mod  2^b  
// where b = number of bits in a Nonce_t object
// The value of the nonces are interpretted as BIG-Endian unsigned integers
void     fNonce( Nonce_t r , Nonce_t n )
{
    r[0] = htonl( 1 + ntohl( n[0] ) ) ;
}

