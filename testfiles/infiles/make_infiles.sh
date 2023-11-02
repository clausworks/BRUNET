len=$1
n_files=$2

for i in $(seq 1 $n_files); do
    infile=test${i}_${len}.in
    openssl rand -base64 ${len} > $infile
done
