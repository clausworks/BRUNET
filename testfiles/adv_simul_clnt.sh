if [ $# -ne 4 ]; then
    echo "Args: addr port in_suffix num_conns"; exit 1
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

for i in $(seq 1 $num_conns); do
    outfile=test${i}.out
    infile=auto_${$}_test${i}_${n_bytes}.in
    echo "nc -q 0 $addr $port < $infile > $outfile &"
    nc -q 0 $addr $port < $infile > $outfile &
done
wait
for i in $(seq 1 $num_conns); do
    infile=auto_${$}_test${i}_${n_bytes}.in
    outfile=test${i}.out
    diff $infile $outfile
    echo Done with $outfile
done
echo All tests complete
