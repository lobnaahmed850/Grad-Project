#!/bin/sh
# Normal traffic to another lab host: browsing, downloads, API calls, DNS and SSH.
# Usage: benign_traffic.sh <peer address> <activities>
peer="$1"
activities="$2"
base="http://$peer:8080"
sizes="300 800 1500 3000 6000 12000 25000 50000 100000 200000 500000 1000000 2000000 5000000 10000000 20000000"

random_int() {
    # Prints a random whole number from 0 up to, but not including, $1.
    # Reads /dev/urandom because BusyBox date has no nanoseconds to seed awk with: every call
    # would return the same number, and each worker would repeat a single activity.
    echo $(( $(od -An -N4 -tu4 /dev/urandom) % $1 ))
}

pause() {
    # Mostly short pauses, with an occasional longer one.
    case "$(random_int 10)" in
        0) sleep "$((1 + $(random_int 4)))" ;;
        *) sleep "0.$((1 + $(random_int 9)))" ;;
    esac
}

browse() {
    # One connection reused for a page and several of its assets.
    set -- -s -o /dev/null "$base/index.html"
    count=$((3 + $(random_int 6)))
    while [ "$count" -gt 0 ]; do
        set -- "$@" -o /dev/null "$base/assets/asset_$((1 + $(random_int 12))).bin"
        count=$((count - 1))
    done
    curl "$@"
}

download() {
    # Small and medium files are common, and large files are rare.
    index=$(random_int 16)
    [ "$index" -ge 13 ] && [ "$(random_int 4)" -ne 0 ] && index=$(random_int 13)
    size=$(echo "$sizes" | awk -v i="$((index + 1))" '{ print $i }')
    curl -s -o /dev/null "$base/file_$size.bin"
}

api_calls() {
    count=$((1 + $(random_int 4)))
    while [ "$count" -gt 0 ]; do
        curl -s -o /dev/null -X POST -H 'Content-Type: application/json' \
            --data "{\"id\":$(random_int 1000)}" "$base/api/items"
        pause
        count=$((count - 1))
    done
}

dns_lookups() {
    for name in files.lab www.lab; do
        dig +short +time=1 +tries=1 "@$peer" "$name" > /dev/null
    done
}

ssh_session() {
    ssh -o ConnectTimeout=3 "root@$peer" 'uname -a; ls -la /srv/files; cat /srv/files/file_3000.bin' > /dev/null 2>&1
}

i=0
while [ "$i" -lt "$activities" ]; do
    case "$(random_int 10)" in
        0|1|2) browse ;;
        3|4|5) download ;;
        6|7) api_calls ;;
        8) dns_lookups ;;
        9) ssh_session ;;
    esac
    pause
    i=$((i + 1))
done
