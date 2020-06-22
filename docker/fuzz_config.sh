#!/bin/sh

echo "FUZZING FAUCET CONFIGURATION FILES"

export PYTHONPATH=/faucet-src:/faucet-src/faucet:/faucet-src/clib

cd /faucet-src/tests/generative/fuzzer/config/

python3 generate_dict.py || exit 0

dictfile="/faucet-src/tests/generative/fuzzer/config/config.dict"

inputfile="/faucet-src/tests/generative/fuzzer/config/examples/"

outputfile="/var/log/afl"
checkfile="$outputfile/fuzzer_stats"

run_file="/faucet-src/tests/generative/fuzzer/config/fuzz_config.py"

if [ -e "$checkfile" ]; then
    start=$(sed -n '1p' $checkfile | cut -c 18-)
    end=$(sed -n '2p' $checkfile | cut -c 18-)
    diff=$(($end-$start))
    cmp="1500"
    if [ "$diff" -gt "$cmp" ]; then
        inputfile="-"
    fi
fi

LIMIT_MB=5000
ulimit -c unlimited; "$run_file" && sudo echo '/var/tmp/core.%h.%e.%t' > /proc/sys/kernel/core_pattern

AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 py-afl-fuzz -m $LIMIT_MB -x "$dictfile" -i "$inputfile" -o "$outputfile" -- /usr/bin/python3 "$run_file"
