#!/bin/sh

if [ "$#" -ne 1 ]; then
  printf "Usage: $0 <trace dataset path>\n"
  exit
fi

cd ../attacks

# Download required k-d tree implementation
if [ ! -d "kdtree" ]; then
  wget https://github.com/pgarrett-scripps/ranged_kdtree/archive/refs/heads/master.zip
  unzip master.zip
  mv ranged_kdtree-master/kdtree ./
  rm -rf ranged_kdtree-master
  rm master.zip
fi

# Run Leaky Streams
printf "Leaky Streams... "
python3 leaky.py attack ../tests/compare/db_leaky.txt "$1" > /dev/null
result=$?
if [ $result -ne 0 ]; then
  printf "Test failed! Leaky Streams exited with code $result, dataset issue?\n" 1>&2
  exit
else
  printf "OK\n"
fi

# Run Walls Have Ears
printf "Walls Have Ears... "
python3 walls.py attack ../tests/compare/db_walls.txt "$1" > /dev/null
result=$?
if [ $result -ne 0 ]; then
  printf "Test failed! Walls Have Ears exited with code $result, dataset issue?\n" 1>&2
  exit
else
  printf "OK\n"
fi

# Run Beauty and the Burst
printf "Beauty and the Burst... "
python3 beauty.py "$1" --extract > /dev/null
result=$?
if [ $result -ne 0 ]; then
  printf "Test failed! Beauty and the Burst exited with code $result, dataset issue?\n" 1>&2
  rm features.txt
  exit
else
  printf "OK\n"
fi
rm features.txt

# report success
printf "All tests succeeded\n"
