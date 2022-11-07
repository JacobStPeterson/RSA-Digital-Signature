#!/bin/bash
echo
echo "Script to test pa-04"
echo "By: Mohamed Aboutabl"
echo

rm -f dispatcher   kdc/kdc             kdc/logKDC.txt    
rm -f amal/amal    amal/logAmal.txt  
rm -f basim/basim  basim/logBasim.txt
rm -f *.mp4

ln -s  ../bunny.mp4       bunny.mp4

echo
echo "=============================="
echo "Compiling Static source"
echo "=============================="
echo
gcc wrappers.c     dispatcher.c -o dispatcher


# make sure Aboutabl executable have the 'x' flag
chmod +x  *_aboutablEx*


echo
echo "********************************************************"
echo "Testing Aboutabl's Code All with itself"
echo "********************************************************"
read -p "Press [Enter] key to continue ..."
echo
    cp  amal_aboutablExecutable            amal/amal
    cp  basim_aboutablExecutable       basim/basim
	gcc kdc/kdc.c      myCrypto.c   -o kdc/kdc      -l:libcrypto.so.1.1

    ./dispatcher

    echo
    echo "======  STUDENT's   KDC    LOG  ========="
    cat kdc/logKDC.txt
    echo

    echo
    echo "======  STUDENT's   Amal   LOG  ========="
    cat amal/logAmal.txt

    echo
    echo "======  STUDENT's   Basim  LOG  ========="
    cat basim/logBasim.txt
    echo
