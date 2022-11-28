/*----------------------------------------------------------------------------
PA-04:  Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   basim.c         SKELETON  

Written By: 
     1-  Jessy Bradshaw and Jacob Peterson
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
    int       fd_A2B , fd_B2A   ;
    FILE     *log ;
    myKey_t   Kb ;    // Basim's master key with the KDC    

    char *developerName = "Code by JESSY BRADSHAW AND JACOB PETERSON" ;
    printf( "\nThis is Basim's   %s\n" ,  developerName ) ;

    if( argc < 3 )
    {
        printf("\nMissing command-line file descriptors: %s <getFr. Amal> "
               "<sendTo Amal>\n\n", argv[0]) ;
        exit(-1) ;
    }
    fd_A2B    = atoi(argv[1]);  // Read from Amal   File Descriptor
    fd_B2A    = atoi(argv[2]);  // Send to   Amal   File Descriptor

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Basim's %s. Could not create log file\n" , developerName ) ;
        exit(-1) ;
    }

    fprintf( log , "\nThis is Basim's %s\n" , developerName ) ;
    fprintf( log , "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n" , fd_A2B , fd_B2A );

    // Get Basim's master keys with the KDC
    if( ! getMasterKeyFromFiles( "basim/basimKey.bin" , "basim/basimIV.bin" , &Kb ) )
    { 
        fprintf( stderr , "\nCould not open Basim's Masker key files\n"); 
        fprintf( log , "\nCould not open Basim's Masker key files\n"); 
        fclose( log ) ; exit(-1) ; 
    }
    fprintf( log , "\nBasim has this Master Kb { key , IV }\n"  ) ;
    BIO_dump_indent_fp ( log , (const char *) Kb.key, SYMMETRIC_KEY_LEN , 4 );
    fprintf( log , "\n" );
    BIO_dump_indent_fp ( log , (const char *) Kb.iv , INITVECTOR_LEN , 4 );
    fprintf( log , "\n") ; 

    //*************************************
    // Receive  & Process   Message 3
    //*************************************
    myKey_t   Ks ;    // Basim's session key with Amal
    char     *IDa;    // Amal's Identity
    Nonce_t   Na2;    // Amal's nonce to Basim.

    // Get MSG3 from Amal
    MSG3_receive( log, fd_A2B, &Kb, &Ks, &IDa, &Na2 ) ; 

    fprintf( log , "Basim received Message 3 from Amal on FD %d "
                   "with the following\n    Session Ks { Key , IV}\n" , fd_A2B  );
    BIO_dump_indent_fp ( log , (const char *) &Ks, sizeof( myKey_t ) , 4 );    fprintf( log , "\n" );

    fprintf( log , "Basim also learned the following\n    IDa= '%s'\n" , IDa );
    fprintf( log , "    Na2 ( %lu Bytes ) is:\n" , NONCELEN );
    BIO_dump_indent_fp ( log , (void *) &Na2, NONCELEN , 4 );    fprintf( log , "\n" );    


    //*************************************
    // Construct & Send    Message 4
    //*************************************
    Nonce_t   fNa2 , Nb ;
    uint8_t  *msg4 ;
    unsigned  LenMsg4 ;

    // Compute fNa2 = f(Na2)
    fNonce( fNa2, Na2 );
 
    fprintf( log , "Basim computed this f(Na2) for MSG4:\n") ;
    BIO_dump_indent_fp ( log , (void *) &fNa2, NONCELEN , 4 );    fprintf( log , "\n" ); 
 
    // Create a random Nonce by B to challenge A
    RAND_bytes( (unsigned char *) Nb , NONCELEN  ); 
    fprintf( log , "Basim Created this nonce Nb for MSG4:\n") ;
    BIO_dump_indent_fp ( log , (void *) &Nb, NONCELEN , 4 );    fprintf( log , "\n" ); 

    LenMsg4 = MSG4_new( log, &msg4, &Ks, &fNa2, &Nb ) ;
    
    // Send MSG4  to  Amal
    // first send len
    write( fd_B2A, &LenMsg4, LENSIZE);
    // second send message 4
    write( fd_B2A, msg4, LenMsg4);
 
    fprintf( log , "Basim Sent the above MSG4 to Amal on FD %d\n" , fd_B2A );
    fflush( log ) ;

    //
    // .....  Missing Code
    //
                  
    //*************************************
    // Receive   & Process Message 5
    //*************************************
    Nonce_t   fNb , fNbCpy;

    // Get MSG5 from Amal
    MSG5_receive( log, fd_A2B, &Ks, &fNb ) ;
    
    fprintf( log , "\nBasim expecting back this fNb in MSG5:\n") ;
    // Compute fNbCpy = f( Nb ) and dump it to log file
    fNonce( fNbCpy, Nb );
    BIO_dump_indent_fp ( log , (void *) &fNbCpy, NONCELEN , 4 );    fprintf( log , "\n" ); 
                  
    fprintf( log , "Basim received Message 5 from Amal on FD %d with this f( Nb ) >>>> " , fd_A2B ) ;
    // Validate f( Nb ) 
    if ( memcmp(fNb, fNbCpy, NONCELEN) == 0  )
    {
        fprintf( log , "VALID\n" ) ;
    }
    else
    {
        fprintf( log , "INVALID >>>> NOT Exiting\n" ) ;
    }
    // Dump received fNb to log file
    BIO_dump_indent_fp ( log , (void *) &fNb, NONCELEN , 4 );    fprintf( log , "\n" );
    fflush( log ) ;


    //*************************************   
    // Final Clean-Up
    //*************************************

    fprintf( log , "\nBasim has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  

    return 0 ;
}
