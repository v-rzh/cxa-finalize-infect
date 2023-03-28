#!/bin/bash
random_name() {
    cat /dev/urandom | tr -c -d 'a-zA-Z0-9' | head -c 10
}

plt_hijack_shell() {
    echo "---------------------------------------------------------------------------------------"
    echo "[*] Testing .plt.got hijack with \"$1\" and a parasite that spawns a shell"
    testtarget="$(random_name)"
    cp -v "$1" "$testtarget"
    "$INFECTOR" -p shell.o "$testtarget"
    fname=`random_name`
    echo "touch $fname" | "./$testtarget"
    stat "$fname"
    if [[ "$?" -ne "0" ]]
    then
        echo "[!] Test failed"
        exit 1
    fi
    rm -v "$fname"
    rm -v "./$testtarget"
    echo "[+] Test passed!"
}

dtors_hijack_shell() {
    echo "---------------------------------------------------------------------------------------"
    echo "[*] Testing __do_global_dtors_aux hijack with \"$1\" and a parasite that spawns a shell"
    testtarget="$(random_name)"
    cp -v "$1" "$testtarget"
    "$INFECTOR" -d shell.o "$testtarget"
    fname=`random_name`
    echo "touch $fname" | "./$testtarget"
    stat "$fname"
    if [[ "$?" -ne "0" ]]
    then
        echo "[!] Test failed"
        exit 1
    fi
    rm -v "$fname"
    rm -v "./$testtarget"
    echo "[+] Test passed!"
}

plt_hijack_hello() {
    echo "----------------------------------------------------------------------------"
    echo "[*] Testing .plt.got hijack with \"$1\" and a simple parasite"
    testtarget="$(random_name)"
    cp -v "$1" "$testtarget"
    "$INFECTOR" -p hello.o "$testtarget"
    "./$testtarget" | grep "ABCD"
    if [[ "$?" -ne "0" ]]
    then
        echo "[!] Test failed"
        exit 1
    fi
    rm -v "./$testtarget"
    echo "[+] Test passed!"
}

dtors_hijack_hello() {
    echo "----------------------------------------------------------------------------"
    echo "[*] Testing __do_global_dtors_aux hijack with \"$1\" and a simple parasite"
    testtarget="$(random_name)"
    cp -v "$1" "$testtarget"
    "$INFECTOR" -d hello.o "$testtarget"
    "./$testtarget" | grep "ABCD"
    if [[ "$?" -ne "0" ]]
    then
        echo "[!] Test failed"
        exit 1
    fi
    rm -v "./$testtarget"
    echo "[+] Test passed!"
}

TESTDIR="./test"
PLTDIR="./plt"
NOPLTDIR="./noplt"
INFECTOR="../infect_cxa_finalize"

make clean && make debug=on
cd "$TESTDIR"

plt_hijack_hello "plt/kill_plt"
dtors_hijack_hello "noplt/kill_noplt"
plt_hijack_shell "plt/kill_plt"
dtors_hijack_shell "noplt/kill_noplt"
plt_hijack_shell "plt/ls_plt"
dtors_hijack_shell "noplt/ls_noplt"

cd -
make clean
