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
echo "Testing STUDENT's Code All with itself"
echo "********************************************************"
read -p "Press [Enter] key to continue ..."
echo
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -l:libcrypto.so.1.1
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -l:libcrypto.so.1.1
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

echo
echo "*******************************************************"
echo "Testing STUDENT's Amal+Basim against Dr. Aboutabl's KDC"
echo "*******************************************************"
read -p "Press [Enter] key to continue ..."
echo

    cp  kdc_aboutablExecutable         kdc/kdc
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -l:libcrypto.so.1.1
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -l:libcrypto.so.1.1

    ./dispatcher

    echo
    echo "======  ABOUTABL'S  KDC    LOG  ========="
    cat kdc/logKDC.txt
    echo

    echo
    echo "======  STUDENT's   Amal   LOG  ========="
    cat amal/logAmal.txt

    echo
    echo "======  STUDENT's   Basim  LOG  ========="
    cat basim/logBasim.txt
    echo

echo
echo "********************************************************"
echo "Testing STUDENT's Basim+KDC  against Dr. Aboutabl's Amal"
echo "********************************************************"
read -p "Press [Enter] key to continue ..."
echo
    cp  amal_aboutablExecutable            amal/amal
    gcc basim/basim.c  myCrypto.c   -o basim/basim  -l:libcrypto.so.1.1
    gcc kdc/kdc.c      myCrypto.c   -o kdc/kdc      -l:libcrypto.so.1.1
    
    ./dispatcher

    echo
    echo "======  STUDENT's   KDC    LOG  ========="
    cat kdc/logKDC.txt
    echo

    echo
    echo "======  ABOUTABL'S  Amal   LOG  ========="
    cat amal/logAmal.txt

    echo
    echo "======  STUDENT's   Basim  LOG  ========="
    cat basim/logBasim.txt
    echo

echo
echo "********************************************************"
echo "Testing STUDENT's Amal+KDC  against Dr. Aboutabl's Basim"
echo "********************************************************"
read -p "Press [Enter] key to continue ..."
echo

    cp  basim_aboutablExecutable       basim/basim
    gcc amal/amal.c    myCrypto.c   -o amal/amal    -l:libcrypto.so.1.1
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
    echo "======  ABOUTABL'S  Basim LOG  ========="
    cat basim/logBasim.txt
    echo

