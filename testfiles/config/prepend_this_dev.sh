if [ $# -ne 2 ]; then
    echo "Args: file_prefix this_dev_addr"; exit 1
fi

file_prefix=$1
this_dev_addr=$2

rm _${file_prefix}_*.yaml

for file in *.yaml; do
    newfile=_${file_prefix}_${file}
    printf "this_device: ${this_dev_addr}\n\n" | cat - "$file" > "$newfile"
done
