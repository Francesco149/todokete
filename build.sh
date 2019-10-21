#!/bin/sh

dir="$(dirname "$0")"
wdir="$(realpath "$dir")"
classpath=""

dep() {
  url="$1"
  sha256="$2"
  name=$(echo "$url" | rev | cut -d'/' -f1 | rev)
  printf '[  ] %s' "$name"
  [ ! -f "$name" ] && curl -LO "$url"
  checksum=$(sha256sum -b "$name" | cut -d' ' -f1) || exit
  if [ "$checksum" != "$sha256" ]; then
    echo "  checksum mismatch"
    echo "  expected: $sha256"
    echo "       got: $checksum"
    exit 1
  fi
  printf '\r[ok] %s' "$name"
  classpath="$classpath:deps/$name"
  echo
}

echo "# checking dependencies"

cd "$wdir"
mkdir deps >/dev/null 2>&1
cd deps
dep https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/3.9.1/okhttp-3.9.1.jar a0d01017a42bba26e507fc6d448bb36e536f4b6e612f7c42de30bbdac2b7785e
dep https://repo1.maven.org/maven2/com/squareup/okio/okio/1.13.0/okio-1.13.0.jar 734269c3ebc5090e3b23566db558f421f0b4027277c79ad5d176b8ec168bb850
dep https://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.6/gson-2.8.6.jar c8fb4839054d280b3033f800d1f5a97de2f028eb8ba2eb458ad287e536f3f25f

compile() {
  echo
  echo "# compiling"
  kotlinc "$1.kt" -cp "$classpath" -include-runtime -d "${1}.jar" || exit
}

run() {
  echo
  echo "# running"
  java -cp "${classpath}:${1}.jar" "${1}Kt" || exit
}

compile_and_run() {
  compile "$1"
  run "$1"
}

cd "$wdir"
compile_and_run Todokete
