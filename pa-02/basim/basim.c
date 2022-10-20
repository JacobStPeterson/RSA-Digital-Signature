int main ( int argc , char * argv[] )
{
    uint8_t digest[EVP_MAX_MD_SIZE] ;
    int     i , fd_in , fd_ctrl , fd_data  ;
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

    fprintf( log , "\nThis is Basim By:   %s.\n\n" , developerName  ) ;


}