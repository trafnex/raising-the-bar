#!/bin/sh

check_output () {
  if grep -F -f "$2" "$1" > /dev/null; then
    printf "OK\n"
  else
    printf "\nTest failed! Output machine incorrect\n" 1>&2
    rm "$2"
    exit
  fi
}

cd ../defenses

# Load provided machines from file
provided="../tests/compare/results_defenses.txt"
result="../tests/results_defenses.txt"

# Compile code to generate defenses
cargo build --release

# Test constant-rate defense
printf "Constant (3.0 Mbps)... "
./target/release/constant | tr -d '[:space:]' > $result       # 3 Mbps
check_output "$provided" "$result"

printf "Constant (2.4 Mbps)... "
./target/release/constant 5000 | tr -d '[:space:]' > $result  # 2.4 Mbps
check_output "$provided" "$result"

# Test best Adapted FRONT configurations
printf "Adapted FRONT 4000, 12... "
./target/release/adapted_front 12 4000 30 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Adapted FRONT 4500, 14... "
./target/release/adapted_front 14 4500 30 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Adapted FRONT 2500, 7... "
./target/release/adapted_front  7 2500 30 | tr -d '[:space:]' > $result
check_output "$provided" "$result"

printf "Adapted FRONT 3500, 5... "
./target/release/adapted_front  5 3500 30 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Adapted FRONT 5000, 7... "
./target/release/adapted_front  7 5000 30 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Adapted FRONT 6000, 9... "
./target/release/adapted_front  9 6000 30 | tr -d '[:space:]' > $result
check_output "$provided" "$result"

printf "Adapted FRONT 5500, 2... "
./target/release/adapted_front  2 5500 30 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Adapted FRONT 6000, 2... "
./target/release/adapted_front  2 6000 30 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Adapted FRONT 6500, 2... "
./target/release/adapted_front  2 6500 30 | tr -d '[:space:]' > $result
check_output "$provided" "$result"

# Test best Adapted RegulaTor configurations
printf "Adapted RegulaTor 500, 0.75... "
./target/release/adapted_regulator  500 0.75 4 20 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Adapted RegulaTor 500, 0.45... "
./target/release/adapted_regulator  500 0.45 4 20 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Adapted RegulaTor 500, 0.25... "
./target/release/adapted_regulator  500 0.25 4 20 | tr -d '[:space:]' > $result
check_output "$provided" "$result"

printf "Adapted RegulaTor 1400, 0.95... "
./target/release/adapted_regulator 1400 0.95 4 20 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Adapted RegulaTor 1300, 0.95... "
./target/release/adapted_regulator 1300 0.95 4 20 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Adapted RegulaTor 1000, 0.95... "
./target/release/adapted_regulator 1000 0.95 4 20 | tr -d '[:space:]' > $result
check_output "$provided" "$result"

printf "Adapted RegulaTor 1500, 0.85... "
./target/release/adapted_regulator 1500 0.85 4 20 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Adapted RegulaTor 1600, 0.95... "
./target/release/adapted_regulator 1600 0.95 4 20 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Adapted RegulaTor 1900, 0.95... "
./target/release/adapted_regulator 1900 0.95 4 20 | tr -d '[:space:]' > $result
check_output "$provided" "$result"

# Test best Scrambler configurations
printf "Scrambler 160, 500... "
./target/release/scrambler 160  500 400 1000 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Scrambler 200, 700... "
./target/release/scrambler 200  700 400 1000 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Scrambler 160, 700... "
./target/release/scrambler 160  700 400 1000 | tr -d '[:space:]' > $result
check_output "$provided" "$result"

printf "Scrambler 160, 1100... "
./target/release/scrambler 160 1100 400 1000 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Scrambler 120, 1100... "
./target/release/scrambler 120 1100 400 1000 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Scrambler 200, 1100... "
./target/release/scrambler 200 1100 400 1000 | tr -d '[:space:]' > $result
check_output "$provided" "$result"

printf "Scrambler 200, 1500... "
./target/release/scrambler 200 1500 400 1000 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Scrambler 160, 1500... "
./target/release/scrambler 160 1500 400 1000 | tr -d '[:space:]' > $result
check_output "$provided" "$result"
printf "Scrambler 120, 1500... "
./target/release/scrambler 120 1500 400 1000 | tr -d '[:space:]' > $result
check_output "$provided" "$result"

# delete tmp results file
rm "$result"

# report success
printf "All tests succeeded\n"
