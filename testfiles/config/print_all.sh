for file in *.yaml; do
    echo "-----------------------------------------------------------"
    printf '%s\n' "$file"
    cat "$file"
    printf '\n'
done
