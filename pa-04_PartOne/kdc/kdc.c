/*----------------------------------------------------------------------------
pLab-04:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   kdc.c   SKELETON

Written By: 
     1- Jessy Bradshaw
     2- Jacob Peterson

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
    int       fd_A2K , fd_K2A   ;
    FILE     *log ;

    if (argc < 3)
        printf ("KDC : Missing Command line arguements, should be 3 was %d", argc);
    
    char *developerName = "Code by Jessy Bradshaw and Jacob Peterson" ;
    printf ( "\nThis is the KDC's %s\n"  , developerName ) ;

    // Check for sufficient number of command-line arguments and get these FDs:
    fd_A2K    = atoi(argv[1]); // Read from Amal   File Descriptor
    fd_K2A    = atoi(argv[2]); // Send to   Amal   File Descriptor

    // open log
    log = fopen("kdc/logKDC.txt", "w");
    if (!log)
        {printf ("KDC : Failed to open log"); exit (-1);}

    // Create an fresh empty log file for  the KDC
    fprintf( log , "\nThis is the KDC's %s\n"  , developerName ) ;

    char myUserName[30] ;
    getlogin_r ( myUserName , 30 ) ;
    time_t  now;
    time( &now ) ;
    fprintf( log , "\nLogged in as user '%s' on %s" , myUserName ,  ctime( &now)  ) ;
       
    fprintf( log , "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n" , fd_A2K , fd_K2A );

    
    // Get Amal's master keys with the KDC and dump it to the log
    myKey_t  *Ka = (myKey_t *) malloc (KEYSIZE);   // Amal's master key with the KDC
    if (getMasterKeyFromFiles( "kdc/amalKey.bin" , "kdc/amalIV.bin" , Ka ) == 0)
        fprintf (log , "KSC : failed to open amals keys");
    fprintf (log, "\nAmal has this Master Ka { key, IV }\n");
    BIO_dump_indent_fp (log, Ka->key, SYMMETRIC_KEY_LEN, 4);
    fprintf (log, "\n");
    BIO_dump_indent_fp (log, Ka->iv, INITVECTOR_LEN, 4);
    
    // Get Basim's master keys with the KDC and dump it to the log
    myKey_t  *Kb = (myKey_t *) malloc (KEYSIZE);    // Basim's master key with the KDC
    if (getMasterKeyFromFiles( "kdc/basimKey.bin" , "kdc/basimIV.bin", Kb) == 0)
        fprintf (log , "KDC : failed to open basims keys");
    fprintf (log, "\nBasim has this Master Ka { key, IV }\n");
    BIO_dump_indent_fp (log, Kb->key, SYMMETRIC_KEY_LEN, 4);
    fprintf (log, "\n");
    BIO_dump_indent_fp (log, Kb->iv, INITVECTOR_LEN, 4);
    fprintf (log, "\n");

    //*************************************   
    // Construct & Send    Message 2
    //*************************************

    // ****  The following is just for pa-04_PartOne **********
    // ****       in lieu of receiving MSG1          **********

    char *IDa = "Amal is Hope", *IDb = "Basim is Smily" ;
    Nonce_t  Na ;
    RAND_bytes( (unsigned char *) Na , NONCELEN  );  // First Nonce by A

    // ***********************************************************

    myKey_t  *Ks = malloc (KEYSIZE);    // Session key for Amal & Basim to use

    // Generate a new Session Key / IV  Ks
    // Use RAND_bytes( ) for both Ks.key and  Ks.iv  
    //  ... some code ..... 
    RAND_bytes ((unsigned char *) Ks->key, SYMMETRIC_KEY_LEN);
    RAND_bytes ((unsigned char *) Ks->iv, INITVECTOR_LEN);
    
    //Ks = MSG2_new( FILE * log , uint8_t **msg2 , const myKey_t *Ka , const myKey_t *Kb , 
    //               const myKey_t *Ks , const char *IDa , const char *IDb , Nonce_t *Na );

    uint8_t *msg2 = malloc (DECRYPTED_LEN_MAX);
    unsigned LenMsg2 = MSG2_new( log , &msg2 , Ka , Kb , Ks , IDa , IDb , &Na ) ;
    
    if(    ( write( fd_K2A , &LenMsg2 , LENSIZE ) != LENSIZE ) 
        || ( write( fd_K2A , msg2 , LenMsg2 )     != LenMsg2 )    )
    {
        fprintf( log , "Unable to send all %lu bytes of of L(M2) || M2 from KDC to A"
                       "... EXITING\n" , LENSIZE+LenMsg2 ) ;
        
        fflush( log ) ;  fclose( log ) ;      free( msg2 )   ;
        exitError( "\nUnable to send MSG2 in KDC\n" );
    }

    fprintf( log ,"The KDC sent the above Encrypted MSG2 to FD=%d Successfully\n" , fd_K2A );
    fflush( log ) ;

    free( msg2 )   ;   // It was allocated memory by MSG2_new()

    //*************************************   
    // Final Clean-Up
    //*************************************
    
    fprintf( log , "\nThe KDC has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;
    close(fd_A2K);
    close(fd_K2A);  
    return 0 ;
}
