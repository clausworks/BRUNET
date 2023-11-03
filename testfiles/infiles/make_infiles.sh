if [ $# -ne 2 ]; then
    echo "Args: file_len n_files"; exit 1
fi

file_len=$1
n_files=$2

exit 0
for i in $(seq 1 $n_files); do
    infile=test${i}_${file_len}.in
    openssl rand -base64 ${file_len} > $infile
done
