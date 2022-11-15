/*----------------------------------------------------------------------------
pLab-04:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   basim.c    SKELETON

Written By     
     1- Jessy Bradshaw
     2- Jacob Peter

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

    char *developerName = "Code by Jessy Bradshaw and Jacob Peterson" ;
    printf( "\nThis is Basim's   %s\n" ,  developerName ) ;

    // Check for sufficient number of command-line arguments and get these FDs:
    fd_A2B    = atoi(argv[1]); // Read from Amal   File Descriptor
    fd_B2A    = atoi(argv[2]); // Send to   Amal   File Descriptor

    // Create an fresh empty log file for  Basim
    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "\nThis is Basim's %s. Could not create my log file\n" , developerName  ) ;
        exit(-1) ;
    }
    fprintf( log , "\nThis is Basim's %s\n" , developerName ) ;

    char myUserName[30] ;
    getlogin_r ( myUserName , 30 ) ;
    time_t  now;
    time( &now ) ;
    fprintf( log , "\nLogged in as user '%s' on %s" , myUserName ,  ctime( &now)  ) ;
   
    fprintf( log , "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n" , fd_A2B , fd_B2A );

    // Get Basim's master keys with the KDC from the .bin files
    if( ! getMasterKeyFromFiles( "basim/basimKey.bin" , "basim/basimIV.bin" , &Kb ) )
    { 
        fprintf( stderr , "\nCould not open Basims's Masker key files\n"); 
        fprintf( log , "\nCould not open Basim's Masker key files\n"); 
        fclose( log ) ; exit(-1) ; 
    }

    // Next, BIO_dump_fp the key * IV to the log file
    fprintf( log , "\nBasim has this Master Kb { key , IV }\n"  ) ;
    BIO_dump_indent_fp ( log , (const char *) Kb.key, SYMMETRIC_KEY_LEN , 4 );
    fprintf( log , "\n" );
    BIO_dump_indent_fp ( log , (const char *) Kb.iv , INITVECTOR_LEN , 4 );
    fprintf( log , "\n") ;

    // That's it for now.
    
    //*************************************   
    // Final Clean-Up
    //*************************************

    fprintf( log , "\nBasim has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  

    return 0 ;
}
