/*----------------------------------------------------------------------------
PA-04:  Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   amal.c         SKELETON  

Written By: 
     1-  Jacob Peterson
     2-  Jessy Bradshaw
Submitted on: 
----------------------------------------------------------------------------*/
#include <linux/random.h>
#include <time.h>
#include <stdlib.h>

#include "../myCrypto.h"

//*************************************
// The Main Loop
//*************************************
int main ( int argc , char * argv[] )
{
    int      fd_A2K , fd_K2A , fd_A2B , fd_B2A  ;
    FILE    *log ;

    
    char *developerName = "Code By:  <<YOUR FULL NAME(s) IN UPPERCASE>>" ;
    
    printf( "\nThis is Amal's    %s\n" , developerName ) ;
    
    if( argc < 5 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. KDC> <sendTo KDC> "
               "<getFr. Basim> <sendTo Basim>\n\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_K2A    = atoi( argv[1] ) ;  // Read from KDC    File Descriptor
    fd_A2K    = atoi( argv[2] ) ;  // Send to   KDC    File Descriptor
    fd_B2A    = atoi( argv[3] ) ;  // Read from Basim  File Descriptor
    fd_A2B    = atoi( argv[4] ) ;  // Send to   Basim  File Descriptor

    log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "\nThis is Amal's %s. Could not create my log file\n" , developerName  ) ;
        exit(-1) ;
    }
    fprintf( log , "\nThis is Amal's %s.\n" , developerName  ) ;

    fprintf( log , "<readFr. KDC> FD=%d , <sendTo KDC> FD=%d , "
                   "<readFr. Basim> FD=%d , <sendTo Basim> FD=%d\n" , 
                   fd_K2A , fd_A2K , fd_B2A , fd_A2B );

    // Get Amal's master key with the KDC
    myKey_t  Ka ;  // Amal's master key with the KDC

    if( ! getMasterKeyFromFiles( "amal/amalKey.bin" , "amal/amalIV.bin" , &Ka ) )
    { 
        fprintf( stderr , "\nCould not open Amal's Masker key files\n"); 
        fprintf( log , "\nCould not open Amal's Masker key files\n"); 
        fclose( log ) ; exit(-1) ; 
    }
    fprintf( log , "\nAmal has this Master Ka { key , IV }\n"  ) ;
    BIO_dump_indent_fp ( log , (uCharPtr) Ka.key, SYMMETRIC_KEY_LEN , 4 );
    fprintf( log , "\n" );
    BIO_dump_indent_fp ( log , (uCharPtr) Ka.iv , INITVECTOR_LEN , 4 );
    fprintf( log , "\n") ; 
        

    fflush( log ) ;

    //*************************************
    // Construct & Send    Message 1
    //*************************************
    char     *IDa = "Choose your IDa" ,  *IDb = "Also, Choose an IDb .. be creative!" ;
    Nonce_t   Na;  

    // Create a random nonce Na
    RAND_bytes( (unsigned char *) Na , NONCELEN  );  // First Nonce by A  
 
    unsigned  LenMsg1 ;
    uint8_t  *msg1 ;
    LenMsg1 = MSG1_new( log , &msg1 , IDa , IDb , &Na ) ;
    
    // Send MSG1 to KDC
    write(fd_A2K, msg1, LenMsg1) ;

    fprintf( log , "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+") ;
    fprintf( log , "Amal sent message 1 ( %d bytes ) to the KDC on FD %d with\n"
                   "    IDa ='%s' , IDb = '%s'\n" , LenMsg1 , fd_A2K , IDa , IDb ) ;
    fprintf( log , "    Na ( %lu Bytes ) is\n" , NONCELEN ) ;
    BIO_dump_indent_fp ( log , (uCharPtr) Na , NONCELEN , 4 ) ;  fprintf( log , "\n") ;

    //*************************************
    // Receive   &   Process Message 2
    //*************************************
    
    myKey_t   Ks ;       // Amal's session key with Basim. Created by the KDC   
    char     *IDb2 ;     // IDb as received from KDC .. must match what was sent in MSG1
    Nonce_t   NaCpy ;
    uint8_t  *tktCipher ;
    unsigned  lenTktCipher , LenKs= sizeof( myKey_t ) ;

    MSG2_receive( log , fd_K2A, &Ka, &Ks, &IDb2, &NaCpy, &lenTktCipher, &tktCipher );


    fprintf( log , "Amal received MSG 2 from the KDC\n" );

    fprintf( log , "    Ks { Key , IV } (%u Bytes ) is:\n" , LenKs );
    BIO_dump_indent_fp ( log , (const char *) &Ks, sizeof( myKey_t ) , 4 );    fprintf( log , "\n" );   

    fprintf( log , "    IDb (%u Bytes):" , lenIDb ) ;

    // Verify the strings IDb = IDb2 both in legth and content
    if(strncmp(IDb, IDb2, lenIDb) != 0)
        fprintf( log , "   ..... MISMATCH .. but NOT Exiting\n" );
    else
        fprintf( log , "   ..... MATCH\n" );

    BIO_dump_indent_fp ( log , IDb2 , lenIDb , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log , "    This is my nonce Na (%lu bytes) I sent in MSG1:\n" , NONCELEN ) ;
    BIO_dump_indent_fp ( log , (void *) &Na , NONCELEN , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log , "    Received Copy of Na (%lu bytes):" , NONCELEN ) ;
    // Verify Na == NaCpy    
    if(Na == NaCpy)
        fprintf( log , "    ..... VALID )\n" ) ;
    else
        fprintf( log , "    ..... INVALID ... but NOT Exiting\n" ) ;

    BIO_dump_indent_fp ( log , (const char *) &NaCpy , NONCELEN , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log , "    Encrypted Ticket (%d bytes):\n" , lenTktCipher ) ;
    BIO_dump_indent_fp ( log , (const char *) tktCipher, lenTktCipher, 4 );       fprintf( log , "\n") ;

    //*************************************
    // Construct & Send    Message 3
    //*************************************
    Nonce_t   Na2 ;
    unsigned  LenNa2 = NONCELEN , LenMsg3 ;
    uint8_t  *msg3 ;

    // Create Second Nonce Na2 by A to challenge B
    fprintf( log , "Amal Created this nonce Na2 for MSG3:\n") ;
    //
    // .....  Missing Code
    //

    LenMsg3 = MSG3_new( /* ... */ ) ;
    
    // Send MSG3 to Basim
    write( /* ... */ ) ;
    fprintf( log , "Amal Sent MSG3 ( %u bytes ) to Basim on FD %d:\n" , LenMsg3 , fd_A2B ) ;
 
    //
    // .....  Missing Code
    //

    //*************************************
    // Receive   & Process Message 4
    //*************************************
    Nonce_t   rcvd_fNa2 , my_fNa2 , Nb ;
 
    // Get MSG4 from Basim
    MSG4_receive( /*...  */ ) ;    
    
    fprintf( log , "\nAmal is expecting back this f( Na2 ) in MSG4:\n") ;
 
    //
    // .....  Missing Code
    //

    fprintf( log , "Basim returned the following f( Na2 )   >>>> " ) ;
    if ( /* ... */  )
        fprintf( log , "VALID\n" ) ;
    else
        fprintf( log , "INVALID >>>> NOT Exiting)\n" ) ;
 
    //
    // .....  Missing Code
    //
       
    fprintf( log , "Amal also received this Nb :\n"  ) ;
 
    //
    // .....  Missing Code
    //


    //*************************************
    // Construct & Send    Message 5
    //*************************************
 
    Nonce_t   fNb ;
    unsigned  LenMsg5 ;
    uint8_t  *msg5 ;


    // Compute fNb = f(Nb)
 
    //
    // .....  Missing Code
    //

    fprintf( log , "Amal computed this F(Nb) for MSG5:\n") ;
 
    //
    // .....  Missing Code
    //

    LenMsg5 = MSG5_new( /* ... */ ) ;
    
    // Send MSG5 to Basim
    write( /* ... */ ) ;
    write( /* ... */ ) ;

     fprintf( log , "Amal Sending the above Message 5 ( %u bytes ) to Basim on FD %d\n"
                   , LenMsg5 , /* ... */ );
 
    //
    // .....  Missing Code
    //


    //*************************************   
    // Final Clean-Up
    //*************************************
   
    fprintf( log , "\nAmal has terminated normally. Goodbye\n" ) ;  
    fclose( log ) ;
    return 0 ;
}

