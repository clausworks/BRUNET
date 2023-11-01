letter=$1
addr=$2
echo $letter
for file in *.yaml; do
    newfile=_${letter}_${file}
    printf "this_device: ${addr}\n\n" | cat - "$file" > "$newfile"
done
