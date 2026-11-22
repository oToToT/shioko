# Prints every sentence of an RFC (plain text) that holds a requirement
# keyword, one per line, as "<section><TAB><sentence>". Page headers and
# footers are dropped and paragraphs broken by a page are joined again.
# The same script produces the list a .req file starts from and the list it
# is checked against, so how exactly it splits sentences does not matter.

function emit(   text, n, cut) {
    text = para
    para = ""
    gsub(/ +/, " ", text)
    while (text != "") {
        # A sentence ends at . ? or ! followed by spaces and a capital,
        # a quote or a bracket.
        if (match(text, /[.?!][")]* [A-Z"(\[]/)) {
            cut = RSTART + RLENGTH - 2
            sentence(substr(text, 1, cut - 1))
            text = substr(text, cut + 1)
        } else {
            sentence(text)
            text = ""
        }
    }
}

function sentence(s) {
    sub(/^ +/, "", s)
    sub(/ +$/, "", s)
    if (s ~ /(^|[^A-Z])(MUST|SHALL|REQUIRED|SHOULD|RECOMMENDED)([^A-Z]|$)/)
        print section "\t" s
}

/\f/ { next }
/\[Page [0-9]+\] *$/ { page = 1; next }
/^RFC [0-9]+ .* [0-9][0-9][0-9][0-9] *$/ { next }
/^ *$/ { gap = 1; next }

# A section heading starts in the first column: "4.1.2.  Client Hello",
# "A.1.  Client" or "Appendix B.  Protocol Data Structures".
/^([0-9]+|[A-Z])(\.[0-9]+)*\.  / || /^Appendix [A-Z]\. / {
    emit()
    section = ($1 == "Appendix") ? $2 : $1
    sub(/\.$/, "", section)
    gap = 0; page = 0
    next
}

{
    line = $0
    sub(/^ +/, "", line)
    if (para != "" && gap && !(page && para !~ /[.:?!][")]*$/)) emit()
    gap = 0; page = 0
    # A line broken after a hyphen continues the same word.
    if (para ~ /[a-z]-$/ && line ~ /^[a-z]/) para = para line
    else para = (para == "" ? line : para " " line)
}

END { emit() }
