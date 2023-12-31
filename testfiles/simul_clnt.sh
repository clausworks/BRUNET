if [ $# -ne 4 ]; then
    echo "Args: addr port in_suffix num_conns"; exit 1
fi

addr=$1
port=$2
in_suffix=$3
num_conns=$4

for i in $(seq 1 $num_conns); do
    outfile=test${i}.out
    infile=infiles/test${i}_$in_suffix.in
    echo "nc -q 0 $addr $port < $infile > $outfile &"
    nc -q 0 $addr $port < $infile > $outfile &
done
wait
for i in $(seq 1 $num_conns); do
    infile=infiles/test${i}_$in_suffix.in
    outfile=test${i}.out
    diff $infile $outfile
    echo Done with $outfile
done
echo All tests complete
