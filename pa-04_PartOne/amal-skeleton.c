/*----------------------------------------------------------------------------
pLab-04:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   amal.c     SKELETON

Written By: 
     1- Your Full Name
     2- Your Full Name

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

    
    char *developerName = "Code by Jessy Bradshaw and Jacob Peterson" ;
    
    printf( "\nThis is Amal's    %s\n" , developerName ) ;
    
    if( argc < 5 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. KDC> <sendTo KDC> "
               "<getFr. Basim> <sendTo Basim>\n\n" , argv[0]) ;
        exit(-1) ;
    }

    fd_K2A    = atoi(argv[1])   // Read from KDC    File Descriptor
    fd_A2K    = atoi(argv[2])   // Send to   KDC    File Descriptor
    fd_B2A    = atoi(argv[3])   // Read from Basim  File Descriptor
    fd_A2B    = atoi(argv[4])   // Send to   Basim  File Descriptor

    log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "\nThis is Amal's %s. Could not create my log file\n" , developerName  ) ;
        exit(-1) ;
    }
    fprintf( log , "\nThis is Amal's %s.\n" , developerName  ) ;

    char myUserName[30] ;
    getlogin_r ( myUserName , 30 ) ;
    time_t  now;
    time( &now ) ;
    fprintf( log , "\nLogged in as user '%s' on %s" , myUserName ,  ctime( &now)  ) ;
   
    fprintf( log , "\n<readFr. KDC> FD=%d , <sendTo KDC> FD=%d , "
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
    BIO_dump_indent_fp ( log , (const char *) Ka.key, SYMMETRIC_KEY_LEN , 4 );
    fprintf( log , "\n" );
    BIO_dump_indent_fp ( log , (const char *) Ka.iv , INITVECTOR_LEN , 4 );
    fprintf( log , "\n") ; 
        

    fflush( log ) ;


    char *IDa = "Amal is Hope", *IDb = "Basim is Smily" ;
    Nonce_t   Na;  

    unsigned lenIDb = strlen(IDb) + 1;   // count the terminating '\0'
    srandom( time( NULL ) ) ;        // Seeding the RNG
    RAND_bytes( (unsigned char *) Na , NONCELEN  );  // First Nonce by A

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
    if( /* the IDb and IDb2 strings are different  */ )
        fprintf( log , "   ..... MISMATCH .. but NOT Exiting\n" );
    else
        fprintf( log , "   ..... MATCH\n" );

    BIO_dump_indent_fp ( log , IDb2 , lenIDb , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log , "    This is my nonce Na (%lu bytes) I sent in MSG1:\n" , NONCELEN ) ;
    BIO_dump_indent_fp ( log , (void *) &Na , NONCELEN , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log , "    Received Copy of Na (%lu bytes):" , NONCELEN ) ;
    // Verify Na == NaCpy    
    if(  /* ....  */  )
        fprintf( log , "    ..... VALID )\n" ) ;
    else
        fprintf( log , "    ..... INVALID ... but NOT Exiting\n" ) ;

    BIO_dump_indent_fp ( log , (const char *) &NaCpy , NONCELEN , 4 ) ;  fprintf( log , "\n") ; 

    fprintf( log , "    Encrypted Ticket (%d bytes):\n" , lenTktCipher ) ;
    BIO_dump_indent_fp ( log , /* ...  */ );       fprintf( log , "\n") ;

    free( IDb2 ) ;  // It was allocated memory by MSG2_receive()
    fflush( log ) ;

    //*************************************   
    // Final Clean-Up
    //*************************************
   
    fprintf( log , "\nAmal has terminated normally. Goodbye\n" ) ;  
    fclose( log ) ;
    return 0 ;
}

