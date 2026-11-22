#!/bin/sh
# Checks the TLA+ specs in spec/ with TLC. For each spec:
#
#   1. model-check it with its .cfg: every check must pass;
#   2. apply each entry of its .broken file: the named checks must fail, and
#      every check in the .cfg must be named by at least one entry;
#   3. print its transition table and compare it with the copy in
#      tests/vectors/ that the Rust tests replay.
#
# Then check the requirement lists in spec/rfc/ (see check_requirements).
#
#   tools/spec.sh            check everything
#   tools/spec.sh --update   also rewrite the tables in tests/vectors/
#   ONLY=Http tools/spec.sh  check one spec (or ONLY=requirements)
#
# Needs `tlc` on the PATH (the Nix dev shell has it), or TLA2TOOLS set to the
# path of tla2tools.jar with `java` on the PATH.
set -eu
cd "$(dirname "$0")/.."
root=$PWD
work=$root/target/spec
update=${1:-}

if [ -n "${TLA2TOOLS:-}" ]; then
    tlc() { java -XX:+UseParallelGC -cp "$TLA2TOOLS" tlc2.TLC "$@"; }
elif ! command -v tlc > /dev/null; then
    echo "tlc not found: run inside 'nix develop' or set TLA2TOOLS" >&2
    exit 1
fi

# run_tlc <dir> <module> <cfg>: output goes to <dir>/<cfg>.log, the exit
# status is TLC's (0 passed, 12 a safety check failed, 13 a liveness check).
run_tlc() {
    (cd "$1" && tlc -workers auto -metadir "$1/states/$3" \
        -config "$3" "$2.tla") > "$1/$3.log" 2>&1
}

fail() {
    echo "FAILED: $1" >&2
    [ -z "${2:-}" ] || tail -n 40 "$2" >&2
    exit 1
}

# Runs one broken copy of a spec and insists that the one named check fails.
# expect_failure <dir> <module> <invariant|property> <Name>
# expect_failure <dir> <module> deadlock
expect_failure() {
    cfg="${4:-$3}.cfg"
    grep -v -E '^(INVARIANT|PROPERTY) ' "$root/spec/$2.cfg" > "$1/$cfg"
    case $3 in
        invariant) echo "INVARIANT $4" >> "$1/$cfg" ;;
        property) echo "PROPERTY $4" >> "$1/$cfg" ;;
        deadlock) ;;
        *) fail "$2.broken: expect must say invariant, property or deadlock, not '$3'" ;;
    esac
    status=0
    run_tlc "$1" "$2" "$cfg" || status=$?
    case $3:$status in
        deadlock:11) return ;;
        deadlock:*) fail "$1: expected a deadlock, TLC exited with $status" "$1/$cfg.log" ;;
    esac
    case $status in
        12 | 13)
            grep -q -e "$4 is violated" -e "Temporal properties were violated" "$1/$cfg.log" ||
                fail "$1: $4 did not fail" "$1/$cfg.log" ;;
        *) # A check that does not depend on the state fails before the run starts.
            grep -q "The invariant of $4 is equal to FALSE" "$1/$cfg.log" ||
                fail "$1: expected $4 to fail, TLC exited with $status" "$1/$cfg.log" ;;
    esac
}

check_spec() {
    module=$1
    table=$2
    dir=$work/$module
    mkdir -p "$dir/spec"
    cp "$root"/spec/*.tla "$root"/spec/*.cfg "$dir/spec/"

    echo "== $module: model check"
    run_tlc "$dir/spec" "$module" "$module.cfg" ||
        fail "$module does not pass" "$dir/spec/$module.cfg.log"
    grep -E 'distinct states found, 0 states left' "$dir/spec/$module.cfg.log" | sed 's/^/   /'

    echo "== $module: broken variants"
    # Split the .broken file into one directory per entry.
    awk -v dir="$dir" '
        /^#/ || /^$/ { next }
        $1 == "break" || $1 == "reach" {
            d = dir "/" $1 "-" $2
            system("mkdir -p " d)
            print $1 > (d "/kind")
            if ($1 == "reach") print "invariant Not" $2 > (d "/expect")
            next
        }
        $1 == "expect" { print $2, $3 >> (d "/expect"); next }
        /^-/ { print substr($0, 2) >> (d "/old"); next }
        /^\+/ { print substr($0, 2) >> (d "/new"); next }
        { print "bad line: " $0 > "/dev/stderr"; exit 1 }
    ' "$root/spec/$module.broken"

    for entry in "$dir"/break-* "$dir"/reach-*; do
        [ -d "$entry" ] || continue
        name=$(basename "$entry")
        cp "$root"/spec/*.tla "$entry/"
        if [ "$(cat "$entry/kind")" = reach ]; then
            # Reaching a state is shown by the check "never there" failing.
            what=${name#reach-}
            sed "s/^=====*\$/Not$what == ~($what)\\
&/" "$root/spec/$module.tla" > "$entry/$module.tla"
        else
            [ -s "$entry/old" ] || fail "$name: no '-' line"
            touch "$entry/new"
            OLD=$entry/old NEW=$entry/new awk '
                BEGIN {
                    while ((getline line < ENVIRON["OLD"]) > 0) old[++m] = line
                    while ((getline line < ENVIRON["NEW"]) > 0) new[++k] = line
                }
                { text[NR] = $0 }
                END {
                    for (i = 1; i + m - 1 <= NR; i++) {
                        for (j = 1; j <= m && text[i + j - 1] == old[j]; j++) ;
                        if (j > m) { hits++; at = i }
                    }
                    if (hits != 1) exit 1
                    for (i = 1; i <= NR; i++) {
                        if (i != at) { print text[i]; continue }
                        for (j = 1; j <= k; j++) print new[j]
                        i += m - 1
                    }
                }
            ' "$root/spec/$module.tla" > "$entry/$module.tla" ||
                fail "$name: the '-' lines must match exactly one place in $module.tla"
        fi
        [ -s "$entry/expect" ] || fail "$name: no expect line"
        while read -r kind check; do
            expect_failure "$entry" "$module" "$kind" "$check"
            echo "   $name: ${check:-the model deadlocks}${check:+ fails}"
        done < "$entry/expect"
    done

    # Every check of the real spec must be shown able to fail.
    for check in $(sed -n -E 's/^(INVARIANT|PROPERTY) //p' "$root/spec/$module.cfg"); do
        cat "$dir"/break-*/expect | grep -q " $check\$" ||
            fail "$module.broken has no entry that makes $check fail"
    done

    [ -n "$table" ] || return 0
    echo "== $module: transition table"
    run_tlc "$dir/spec" "${module}Table" "${module}Table.cfg" ||
        fail "${module}Table does not run" "$dir/spec/${module}Table.cfg.log"
    {
        echo "# Generated by tools/spec.sh from spec/$module.tla. Do not edit."
        sed -n 's/^"\(.*\)"$/\1/p' "$dir/spec/${module}Table.cfg.log" | LC_ALL=C sort
    } > "$dir/table.txt"
    if [ "$update" = --update ]; then
        cp "$dir/table.txt" "$root/tests/vectors/$table"
    fi
    cmp -s "$dir/table.txt" "$root/tests/vectors/$table" ||
        fail "tests/vectors/$table is out of date: run tools/spec.sh --update"
    echo "   tests/vectors/$table: $(($(wc -l < "$dir/table.txt") - 1)) rows, up to date"
}

# Checks one requirement list, spec/rfc/<name>.req, against the RFC text
# next to it. Every sentence of the RFC that holds MUST, SHALL, REQUIRED,
# SHOULD or RECOMMENDED has to be listed, with at least one status:
#
#   = row <line>      a line of a transition table in tests/vectors/ shows it
#   = check <M>.<N>   check N of spec/M.cfg establishes it
#   = test <name>     the Rust test or proof `fn <name>` establishes it
#   = code <rule>     a rule for the Rust code and its tests
#   = peer <...>      it binds the other party
#   = unused <...>    it is about a feature we do not have
#   = deviation <...> we knowingly do otherwise
#   = info <...>      it is not a requirement on an implementation
#
# A "= gap" status, or none at all, fails the check.
check_requirements() {
    name=$1
    dir=$work/$name
    mkdir -p "$dir"
    echo "== $name: requirements"
    awk -f "$root/tools/rfc-sentences.awk" "$root/spec/rfc/$name.txt" |
        LC_ALL=C sort > "$dir/rfc"
    awk '
        /^@ / { section = substr($0, 3); next }
        /^> / { print section "\t" substr($0, 3) }
    ' "$root/spec/rfc/$name.req" | LC_ALL=C sort > "$dir/req"
    cmp -s "$dir/rfc" "$dir/req" || {
        diff "$dir/rfc" "$dir/req" | head -n 20 >&2
        fail "spec/rfc/$name.req does not list exactly the requirement sentences of $name"
    }
    cat "$root"/tests/vectors/*_fsm.txt > "$dir/rows"
    for cfg in "$root"/spec/*.cfg; do
        sed -n -E "s/^(INVARIANT|PROPERTY) /$(basename "$cfg" .cfg)./p" "$cfg"
    done > "$dir/checks"
    grep -r -h -o -E 'fn [a-z0-9_]+\(' "$root/src" | sed -e 's/^fn //' -e 's/($//' > "$dir/tests"
    awk -v rows="$dir/rows" -v checks="$dir/checks" -v tests="$dir/tests" '
        BEGIN {
            while ((getline line < rows) > 0) row[line] = 1
            while ((getline line < checks) > 0) check[line] = 1
            while ((getline line < tests) > 0) test[line] = 1
        }
        function bad(why) { print FILENAME ":" FNR ": " why > "/dev/stderr"; errors++ }
        function close_entry() { if (open && !statuses) bad("sentence without a status"); open = 0 }
        /^#/ || /^$/ || /^@ / { next }
        /^> / { close_entry(); open = 1; statuses = 0; at = FNR; next }
        /^= / {
            statuses++
            kind = $2
            rest = substr($0, length(kind) + 4)
            count[kind]++
            if (kind == "row") { if (!(rest in row)) bad("no such table line: " rest) }
            else if (kind == "check") { if (!(rest in check)) bad("no such check: " rest) }
            else if (kind == "test") { if (!(rest in test)) bad("no such test: " rest) }
            else if (kind == "gap") bad("still open: " rest)
            else if (kind !~ /^(code|peer|unused|deviation|info)$/) bad("unknown status: " kind)
            else if (rest == "") bad("status without text")
            next
        }
        { bad("unexpected line") }
        END {
            close_entry()
            printf "  "
            for (k in count) printf " %s %d", k, count[k]
            printf "\n"
            exit errors ? 1 : 0
        }
    ' "$root/spec/rfc/$name.req" || fail "spec/rfc/$name.req has problems"
    echo "   $(wc -l < "$dir/rfc" | tr -d ' ') sentences accounted for"
}

rm -rf "$work"
mkdir -p "$work"
for module in ${ONLY:-Handshake Http Server}; do
    case $module in
        Handshake) check_spec Handshake handshake_fsm.txt ;;
        Http) check_spec Http http_fsm.txt ;;
        Server) check_spec Server "" ;;
        requirements) ;;
        *) fail "unknown spec: $module" ;;
    esac
done
if [ -z "${ONLY:-}" ] || [ "$ONLY" = requirements ]; then
    for name in rfc8446 rfc9110 rfc9112 rfc10024; do
        check_requirements "$name"
    done
fi
echo "== all specs passed"
