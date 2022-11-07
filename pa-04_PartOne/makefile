all:
	gcc amal/amal.c    myCrypto.c   -o amal/amal     -l:libcrypto.so.1.1
	gcc basim/basim.c  myCrypto.c   -o basim/basim   -l:libcrypto.so.1.1
	gcc kdc/kdc.c      myCrypto.c   -o kdc/kdc       -l:libcrypto.so.1.1
	gcc genMasterKey.c              -o genMasterKey  -l:libcrypto.so.1.1
	gcc wrappers.c     dispatcher.c -o dispatcher


clean:
	rm -f dispatcher   genMasterKey        kdc/kdc            kdc/logKDC.txt    
	rm -f amal/amal    amal/logAmal.txt  
	rm -f basim/basim  basim/logBasim.txt  
	rm -f *.mp4        kdc/*.bin           amal/*.bin         basim/*.bin
