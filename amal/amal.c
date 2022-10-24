

#include "../myCrypto.h"


int main ( int argc , char * argv[] )
{
    uint8_t digest[EVP_MAX_MD_SIZE] ;
    int     i , fd_in , fd_ctrl , fd_data  ;
    size_t  mdLen ;
    FILE    *log ;
    
    char *developerName = "Jessy Bradshaw and Jacob Peterson" ;
    
    printf( "\nThis is Amal  By:    %s\n\n" , developerName ) ;

    // confirm correct number of arguements
    if( argc < 3 )
    {
        printf("Missing command-line arguments: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
        exit(-1) ;
    }

    // get AtoB ctrl and AtoB data
    fd_ctrl   = atoi( argv[1] ) ;
    fd_data = atoi( argv[2] ) ;

    // open file log
    log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "Amal: Could not create log file\n");
        exit(-1) ;
    }

    // get amals private key
    RSA *amals_priv_key = NULL;
    amals_priv_key = getRSAfromFile("amal/amal_priv_key.pem", 0);
    if (!amals_priv_key)
        {fprintf (stderr, "Amal : failed to read Amal's private key.\n"); exit (-1);}

    // print to log
    fprintf( log , "\nThis is Amal By:   %s.\n\n" , developerName  ) ;
    
	fd_in   = open("bunny.mp4" , O_RDONLY , S_IRUSR | S_IWUSR ) ;
    if (fd_in == -1)
        { fprintf ( stderr, "Amal: Failed to open plaintext file\n"); exit(-1);}

    // print info to log
    fprintf (log, "Amal : I will send digest to FD %d and file to FD %d\n",fd_ctrl, fd_data);
    fprintf (log, "Amal : Starting to digest the input file\n");

	//fflush(log);

    // perform hash
	mdLen   = fileDigest( fd_in , fd_data , digest ) ;  // also dump file to Basim
    //printf ("\n1\n");
    // print info thats in the digest
    fprintf (log, "\nAmal : Here is the digest of the file:\n");
    BIO_dump_fp (log, (const char*) digest, mdLen);

    // create a digital signature by encrypting the hash with Amal's private key
    // note to self: add a null terminating character to end
    uint8_t *encrypt_hash = calloc (RSA_size(amals_priv_key) + 1, sizeof(uint8_t));
    int en_len = RSA_private_encrypt(mdLen, digest, encrypt_hash, amals_priv_key, RSA_PKCS1_PADDING);

    // print encrypted hash
    fprintf (log, "\nAmal: Here is my signature on the file:\n");
    BIO_dump_fp (log, (const char*) encrypt_hash, en_len);

    // send digital signature via the control file descriptor
    write (fd_ctrl,(const void*)encrypt_hash,(size_t)en_len);

    // Clean up the crypto library
    RSA_free( amals_priv_key  ) ;
    free (encrypt_hash);
    close(fd_in);
    close(fd_ctrl);
    close(fd_data);
    fclose(log);
}
