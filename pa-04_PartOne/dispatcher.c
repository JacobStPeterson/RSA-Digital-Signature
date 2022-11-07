/*-------------------------------------------------------------------------------
PA-04_PartONE: Enhanced Needham-Schoeder Protocol

FILE:   dispatcher.c

Written By: 
     1- Jessy Bradshaw
Submitted on: 
-------------------------------------------------------------------------------*/

#include "wrappers.h"
#include <sys/wait.h>

#define   READ_END	0
#define   WRITE_END	1
#define   STDIN  0
#define   STDOUT 1
//--------------------------------------------------------------------------
int main( int argc , char *argv[] )
{
    pid_t  amalPID , basimPID , kdcPID ; 
    int    AtoB[2] , BtoA[2] , AtoK[2], KtoA[2] ;  // Amal, Basim, and KDC pipes
    char   arg1[20] , arg2[20] , arg3[20] , arg4[20] ;
    
    Pipe( AtoB ) ;  // create pipe for Amal-to-Basim
    Pipe( BtoA ) ;  // create pipe for Basim-to-Amal
	Pipe( AtoK ) ;  // create pipe for Amal-to-KDC
	Pipe( KtoA ) ;  // create pipe for KDC-to-Amal

    printf("\nDispatcher started and created all four pipes\n") ;
    printf("Amal-to-Basim pipe: read=%d  write=%d\n", AtoB[READ_END] , AtoB[WRITE_END] ) ;
    printf("Basim-to-Amal pipe: read=%d  write=%d\n", BtoA[READ_END] , BtoA[WRITE_END] ) ;
    printf("Amal-to-KDC pipe: read=%d  write=%d\n",   AtoK[READ_END] , AtoK[WRITE_END] ) ;
    printf("KDC-to-Amal pipe: read=%d  write=%d\n",   KtoA[READ_END] , KtoA[WRITE_END] ) ;

    // Create three child processes:
    amalPID = Fork() ;
    if ( amalPID == 0 )
    {    
        // This is the Amal process.
        // Amal will not use these ends of the pipes, decrement their 'count'
        close( AtoB[READ_END]  ) ;
        close( BtoA[WRITE_END] ) ;
		close( AtoK[READ_END]  ) ;
		close( KtoA[WRITE_END] ) ;
		
        // Prepare the file descriptors as args to Amal
        snprintf( arg1 , 20 , "%d" , KtoA[READ_END]   ) ;
        snprintf( arg2 , 20 , "%d" , AtoK[WRITE_END]  ) ;
        snprintf( arg3 , 20 , "%d" , BtoA[READ_END]   ) ;
        snprintf( arg4 , 20 , "%d" , AtoB[WRITE_END]  ) ;
        
        // Now, Start Amal
        char * cmnd = "./amal/amal" ;
        execlp( cmnd , "Amal" , arg1 , arg2 , arg3 , arg4 , NULL );

        // the above execlp() only returns if an error occurs
        perror("ERROR starting Amal" );
        exit(-1) ;      
    } 
    else
    {    // This is still the Dispatcher process 
        basimPID = Fork() ;
        if ( basimPID == 0 )
        {  
            // This is the Basim process
            // Basim will not use these ends of the pipes, decrement their 'count'
            close( AtoB[WRITE_END] ) ;
            close( BtoA[READ_END] ) ;
			close( AtoK[WRITE_END] ) ;
			close( AtoK[READ_END] ) ;
			close( KtoA[WRITE_END] ) ;
			close( KtoA[READ_END] ) ;
            
            // Prepare the file descriptors as args to Basim
            snprintf( arg1 , 20 , "%d" , AtoB[READ_END] ) ;
            snprintf( arg2 , 20 , "%d" , BtoA[WRITE_END] ) ;

            char * cmnd = "./basim/basim" ;
            execlp( cmnd , "Basim" , arg1 , arg2 , NULL );

            // the above execlp() only returns if an error occurs
            perror("ERROR starting Basim" ) ;
            exit(-1) ;
        }
        else
        {   // This is still the parent Dispatcher  process
	        kdcPID = Fork() ;
			if ( kdcPID == 0 )
			{  
				// This is the KDC process
				// KDC will not use these ends of the pipes, decrement their 'count'
				close( AtoB[WRITE_END] ) ;
				close( AtoB[READ_END]  ) ;
				close( BtoA[WRITE_END] ) ;
				close( BtoA[READ_END]  ) ;
				close( AtoK[WRITE_END] ) ;
				close( KtoA[READ_END]  ) ;
				
				// Prepare the file descriptors as args to KDC
				snprintf( arg1 , 20 , "%d" , AtoK[READ_END] ) ;
				snprintf( arg2 , 20 , "%d" , KtoA[WRITE_END] ) ;

				char * cmnd = "./kdc/kdc" ;
				execlp( cmnd , "KDC" , arg1 , arg2 , NULL );

				// the above execlp() only returns if an error occurs
				perror("ERROR starting Basim" ) ;
				exit(-1) ;
			}
			else
			{
				// close all ends of the pipes so that their 'count' is decremented
				close( AtoB[WRITE_END] ); 
				close( AtoB[READ_END]  );   
				close( BtoA[WRITE_END] ); 
				close( BtoA[READ_END]  );   
				close( AtoK[WRITE_END] ); 
				close( AtoK[READ_END]  );   
				close( KtoA[WRITE_END] ); 
				close( KtoA[READ_END]  );   

				printf("\nDispatcher is now waiting for Amal to terminate\n") ;
				int  exitStatus ;
				waitpid( amalPID , &exitStatus , 0 ) ;
				printf("\nAmal terminated ... "  ) ;
				if (  WIFEXITED( exitStatus ) )
						printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;

				printf("\nDispatcher is now waiting for Basim to terminate\n") ;
				waitpid( basimPID , &exitStatus , 0 ) ;
				printf("\nBasim terminated ... " ) ;
				if (  WIFEXITED( exitStatus ) )
						printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;
					
				printf("\nDispatcher is now waiting for KDC to terminate\n") ;
				waitpid( kdcPID , &exitStatus , 0 ) ;
				printf("\nKDC terminated ... " ) ;
				if (  WIFEXITED( exitStatus ) )
						printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;

				printf("\nThe Dispatcher process has terminated\n") ;     
			}
		}
    }  
}

