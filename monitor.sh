#!/bin/sh

dir="$(dirname "$0")"
wdir="$(realpath "$dir")"
uri="file://$wdir/todokete.db?mode=ro&journal_mode=WAL&synchronous=NORMAL"
uri="${uri}&journal_size_limit=500"

while true; do
  microtime=$(date +%s%N | cut -b1-13)
  old=$((microtime - 86400000))
  if out=$(sqlite3 "$uri" ".timeout 2000" \
    "
    select count(*), cast(avg(stars) as int), max(stars),
      min(case when status >= 24 then stars else 1000000000 end),
      sum(case when lastLogin < $old then 1 else 0 end),
      sum(case when status < 24 then 1 else 0 end)
    from accounts;
  " 2>/dev/null)
  then
    clear
    echo "$out" | awk -F'|' '{
      printf "total accounts: %d\n",$1
      printf " average stars: %d\n",$2
      printf "     max stars: %d\n",$3
      printf "     min stars: %d\n",$4
      printf "stale accounts: %d\n",$5
      printf "   no tutorial: %d\n",$6
    }'
  fi
  sleep 2
done
