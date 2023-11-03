if [ $# -ne 5 ]; then
    echo "Args: addr port n_bytes num_conns [delay | \"nodelay\"]"; exit 1
fi

addr=$1
port=$2
n_bytes=$3
num_conns=$4
delay=$5


# Generate random test files
for i in $(seq 1 $num_conns); do
    infile=auto_${$}_test${i}_${n_bytes}.in
    openssl rand ${n_bytes} > $infile
done

# Run tests
for i in $(seq 1 $num_conns); do
    infile=auto_${$}_test${i}_${n_bytes}.in
    outfile=auto_${$}_test${i}_${n_bytes}.out
    echo "python3 randomclnt.py $addr $port $delay < $infile > $outfile &"
    python3 randomclnt.py $addr $port $delay < $infile > $outfile &
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
