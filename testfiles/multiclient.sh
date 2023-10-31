testfile=$1
num_conns=$2

for i in $(seq 1 $num_conns); do
    outfile=test${i}.out
    echo "nc -q 0 10.0.0.2 1234 < $testfile > $outfile &"
    nc -q 0 10.0.0.2 1234 < $testfile > $outfile &
done
wait
for i in $(seq 1 $num_conns); do
    diff $testfile $outfile
    echo Done with $outfile
done
echo All tests complete
