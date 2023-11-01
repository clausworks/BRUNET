for i in $(seq 1 $2); do
    infile=test${i}_${1}.in
    openssl rand -base64 ${1} > $infile
done
