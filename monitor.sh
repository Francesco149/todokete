#!/bin/sh

dir="$(dirname "$0")"
wdir="$(realpath "$dir")"
cd "$wdir"

while true; do
  microtime=$(date +%s%N | cut -b1-13)
  old=$((microtime - 86400000))
  if out=$(sqlite3 todokete.db "
    select count(*), cast(avg(stars) as int), max(stars), min(stars),
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