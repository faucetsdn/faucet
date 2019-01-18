#!/bin/sh
dictfile="/faucet-src/tests/fuzzer/dict/packet.dict"
inputfile="/faucet-src/tests/fuzzer/packet/"
outputfile="/var/log/afl/"
checkfile="$outputfile/fuzzer_stats"

if [ -e "$checkfile" ]; then
    start=$(sed -n '1p' $checkfile | cut -c 18-)
    end=$(sed -n '2p' $checkfile | cut -c 18-)
    diff=$(($end-$start))
    cmp="1500"
    if [ "$diff" -gt "$cmp" ]; then
        inputfile="-"
    fi
fi

AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 py-afl-fuzz -m 5000 -x "$dictfile" -i "$inputfile" -o "$outputfile" -- /usr/bin/python3 /faucet-src/tests/fuzzer/fuzz_packet.py
