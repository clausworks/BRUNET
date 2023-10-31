addr=$1
port=$2
testfile=$3
num_conns=$4

for i in $(seq 1 $num_conns); do
    outfile=test${i}.out
    echo "nc -q 0 $addr $port < $testfile > $outfile &"
    nc -q 0 $addr $port < $testfile > $outfile &
done
wait
for i in $(seq 1 $num_conns); do
    diff $testfile $outfile
    echo Done with $outfile
done
echo All tests complete
