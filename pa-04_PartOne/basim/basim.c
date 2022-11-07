/*----------------------------------------------------------------------------
pLab-04:  Intro to Enhanced Needham-Schroeder Key-Exchange with TWO-way Authentication

FILE:   basim.c    SKELETON

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
    int       fd_A2B , fd_B2A   ;
    FILE     *log ;
    myKey_t   Kb ;    // Basim's master key with the KDC    

    char *developerName = "Code by *** MUST   WRITE  YOUR  FULL NAME(S)  HERE***" ;
    printf( "\nThis is Basim's   %s\n" ,  developerName ) ;

    // Check for sufficient number of command-line arguments and get these FDs:
    fd_A2B    = // Read from Amal   File Descriptor
    fd_B2A    = // Send to   Amal   File Descriptor

    // Create an fresh empty log file for  Basim

    fprintf( log , "\nThis is Basim's %s\n" , developerName ) ;

    char myUserName[30] ;
    getlogin_r ( myUserName , 30 ) ;
    time_t  now;
    time( &now ) ;
    fprintf( log , "\nLogged in as user '%s' on %s" , myUserName ,  ctime( &now)  ) ;
   
    fprintf( log , "\n<readFr. Amal> FD=%d , <sendTo Amal> FD=%d\n" , fd_A2B , fd_B2A );

    // Get Basim's master keys with the KDC from the .bin files

    // Next, BIO_dump_fp the key * IV to the log file


    // That's it for now.
    
    //*************************************   
    // Final Clean-Up
    //*************************************

    fprintf( log , "\nBasim has terminated normally. Goodbye\n" ) ;
    fclose( log ) ;  

    return 0 ;
}
