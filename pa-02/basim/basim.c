
#include "../myCrypto.h"


int main ( int argc , char * argv[] )
{
    uint8_t digest1[EVP_MAX_MD_SIZE] ;
    uint8_t digest2[EVP_MAX_MD_SIZE] ;
    int     fd_in , fd_out, fd_ctrl , fd_data  ;
    size_t  mdLen ;
    FILE    *log ;
    
    char *developerName = "Jessy Bradshaw and Jacob Peterson" ;
    
    printf( "\nThis is Basim  By:    %s\n\n" , developerName ) ;

    if( argc < 3 )
    {
        printf("Missing command-line arguments: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_ctrl   = atoi( argv[1] ) ;
    fd_data = atoi( argv[2] ) ;

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "Basim: Could not create log file\n");
        exit(-1) ;
    }

    // get amals public key
    RSA *amals_pub_key = NULL;
    amals_pub_key = getRSAfromFile("amal/amal_pubKey.pem", 1);
    if (!amals_pub_key)
        {fprintf (stderr, "Basim : failed to read Amal's public key.\n"); exit (-1);}

    fprintf( log , "\nThis is Basim By:   %s.\n\n" , developerName  ) ;
    
    // might need params from amal.c also not sure where bunny.cpy gets created
    fd_out   = open("bunny.cpy" , O_WRONLY | O_CREAT , S_IRUSR | S_IWUSR) ;
    if (fd_in == -1)
        { fprintf ( stderr, "Basim: Failed to create bunny.cpy\n"); exit(-1);}

    //uint8_t buffer[ INPUT_CHUNK ];
    //ssize_t len;
    //while ((len = read(fd_data, buffer, INPUT_CHUNK)) > 0) {

    //if (write (fd_out, buffer, len) != len)
    //    {fprintf (stderr, "Basim: failed to save bunny data\n"); exit(-1);}    
    //}

    // print info to log
    fprintf (log, "Basim : I will recieve digest from FD %d and file from FD %d\n",fd_ctrl, fd_data);
    fprintf (log, "Basim : Starting to recieve incoming file and compute its digest\n");

    // receive mp4 from fd_data, call filedigest to compute digest1, and save local copy as bunny.cpy fd_out

    mdLen = fileDigest( fd_data , fd_out , digest1 );
    
    // print digest info
    fprintf (log, "\nBasim: Here is locally-computed the digest of the incoming file:\n");
    BIO_dump_fp (log, (const char*) digest1, mdLen);

    // receive digital signature over ctrl pipe, decrypt with public key to get digest2
    uint8_t *encrypt_hash = calloc (RSA_size(amals_pub_key) + 1, sizeof(uint8_t));
    size_t en_ha_len;
    if ((en_ha_len = read(fd_ctrl, encrypt_hash,RSA_size(amals_pub_key))) <= 0)
        {printf ("Basim: unable to read Amals signature\n"); exit(-1);}

    fprintf (log, "\nBasim: I received the following signature from Amal:\n");
    BIO_dump_fp (log, (const char*)encrypt_hash, RSA_size(amals_pub_key));

    // decrypt the encrypted hash
    size_t de_len = RSA_public_decrypt (RSA_size(amals_pub_key), encrypt_hash, digest2, amals_pub_key, RSA_PKCS1_PADDING);

    fprintf (log, "\nBasim: here is Amal's decrypted signature:\n");
    BIO_dump_fp (log, (const char*) digest2, de_len);

    // compare digests
    char* validity;
    if (memcmp (digest1, digest2,(long unsigned int) de_len) == 0) {
        validity = "Valid";
    } else {
        validity = "InValid";    
    }

    fprintf (log, "\nBasim: Amal's signature is %s\n", validity);
    
    close(fd_data);
    close(fd_ctrl);
    close(fd_out);
    fclose(log);
}
