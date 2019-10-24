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
dep https://repo1.maven.org/maven2/com/tylerthrailkill/helpers/pretty-print/2.0.2/pretty-print-2.0.2.jar e35f7e5e989a13147d734777177bdf4a1f27df230e81b317233c61c1db80f8a0
dep https://repo1.maven.org/maven2/io/github/microutils/kotlin-logging/1.6.22/kotlin-logging-1.6.22.jar d2ed7708bd1e85d0f95158ce3c2d147ae226a92944d2b3dbf65d7796edd1f15c
dep https://repo1.maven.org/maven2/ch/qos/logback/logback-classic/1.3.0-alpha4/logback-classic-1.3.0-alpha4.jar 6a8d8f9b9a25a44451363d1e3be1d31765686908f7dd17b1d75be4e3e5337cd0
dep https://repo1.maven.org/maven2/com/ibm/icu/icu4j/63.1/icu4j-63.1.jar 0940c61d12667413a58206a010ab5ca0758cc44ad9e9957ea98e0f871ab5eda0
dep https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-reflect/1.3.11/kotlin-reflect-1.3.11.jar b8472ffb8319c8b53861effe6aa95b1521f1cfdaac3fc16033e35864f112496d
dep https://repo1.maven.org/maven2/org/slf4j/slf4j-simple/1.6.1/slf4j-simple-1.6.1.jar 14c6e9bdff71af1fb7054f9326159cea8bb5c1eb238159179ca911149c138e1d
dep https://repo1.maven.org/maven2/org/slf4j/slf4j-api/1.7.25/slf4j-api-1.7.25.jar 18c4a0095d5c1da6b817592e767bb23d29dd2f560ad74df75ff3961dbde25b79

compile() {
  echo
  echo "# compiling"
  kotlinc "$1.kt" -cp "$classpath" -include-runtime \
    -Xuse-experimental=kotlin.ExperimentalUnsignedTypes \
    -d "${1}.jar" || exit
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
