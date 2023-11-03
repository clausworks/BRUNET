if [ $# -ne 4 ]; then
    echo "Args: addr port n_bytes num_conns"; exit 1
fi

addr=$1
port=$2
n_bytes=$3
num_conns=$4


# Generate random test files
for i in $(seq 1 $num_conns); do
    infile=auto_${$}_test${i}_${n_bytes}.in
    openssl rand ${n_bytes} > $infile
done

# Run tests
for i in $(seq 1 $num_conns); do
    infile=auto_${$}_test${i}_${n_bytes}.in
    outfile=auto_${$}_test${i}_${n_bytes}.out
    echo "nc -q 0 $addr $port < $infile > $outfile &"
    nc -q 0 $addr $port < $infile > $outfile &
done
wait
# Check results
for i in $(seq 1 $num_conns); do
    infile=auto_${$}_test${i}_${n_bytes}.in
    outfile=auto_${$}_test${i}_${n_bytes}.out
    diff $infile $outfile
    echo Done with $outfile
done

# Delete test files
for i in $(seq 1 $num_conns); do
    infile=auto_${$}_test${i}_${n_bytes}.in
    outfile=auto_${$}_test${i}_${n_bytes}.out
    rm ${infile}
    rm ${outfile}
done

echo All tests complete
