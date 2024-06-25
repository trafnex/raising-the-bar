# raising-the-bar

This repository contains code from the following paper:
 - David Hasselquist, Ethan Witwer, August Carlson, Niklas Johansson, and Niklas Carlsson. "Raising the Bar: Improved Fingerprinting Attacks and Defenses for Video Streaming Traffic". Proceedings on Privacy Enhancing Technologies (PoPETs), volume 4, 2024.

If you use the code in this repository or the linked datasets in your work, please include a reference to the paper.
Some of the code is based on other research, as noted below - please cite any other relevant papers as well to credit their authors.

## Overview

We provide implementations of the following three video fingerprinting attacks:
 - Leaky Streams [1] (`attacks/leaky.py`)
 - Walls Have Ears [2] (`attacks/walls.py`)
 - Beauty and the Burst [3] (`attacks/beauty.py`)

Four defenses implementations are also included, described in detail in the paper. They are:
 - Constant (`defenses/src/bin/constant.rs`)
 - Adapted FRONT (`defenses/src/bin/adapted_front.rs`)
 - Adapted RegulaTor (`defenses/src/bin/adapted_regulator.rs`)
 - Scrambler (`defenses/src/bin/scrambler.rs`)

For further reading, refer to the FRONT [4], RegulaTor [5], and Maybenot [6] papers.

**Attacks and defenses are provided for research purposes only.**

## Setup Tasks

You will need `python3`/`pip` to run the attacks; they can be downloaded via your distribution's package manager. For example:

```bash
  sudo apt update
  sudo apt install python3 python3-pip
```

Next, use `pip` to install the modules specified in `requirements.txt` (note that CUDA version 12.2 is required for Keras/TensorFlow - feel free to remove these dependencies if you do not plan to run Beauty and the Burst):

```bash
  sudo pip3 install -r requirements.txt
```

The Leaky Streams attack uses the k-d tree implementation that can be found [here](https://github.com/pgarrett-scripps/ranged_kdtree); the `kdtree` directory should be placed under `attacks`. This can be done as follows (from the root directory of the repository):

```bash
  wget https://github.com/pgarrett-scripps/ranged_kdtree/archive/refs/heads/master.zip
  unzip master.zip
  mv ranged_kdtree-master/kdtree/ attacks/
  rm -rf ranged_kdtree-master/
  rm master.zip
```

Finally, the defense code requires `cargo`. Follow the [official instructions](https://doc.rust-lang.org/cargo/getting-started/installation.html) to install it.

## Code Usage

### Attacks

The Leaky Streams and Walls Have Ears attacks have two modes:
 - `setup`, to build a fingerprint database using encoded segments
 - `attack`, to evaluate on a dataset of collected traces

The first positional argument is the mode, and the second is the path to the database file (to save to/load from). In attack mode, the third positional argument is the root path of the _trace_ dataset, e.g. _LongEnough_, to test on. The optional `-s/--start` and `-e/--end` arguments allow you to specify the start and end offsets to attack, in seconds from the end of a trace (default last 60 seconds).

We provide database files for _LongEnough_ - see below. To use another dataset, you will need to run setup mode. In this case, the third positional argument is the root path of the _segment_ dataset that will be used to generate the database. Please refer to the attack code for specifics on how the segment dataset should be formatted or to make modifications. In gist, the format resembles the _LongEnough_ trace dataset, but with a `segments` subdirectory for each video containing media data at varying qualities.

For Beauty and the Burst, the only required argument is the root path of the trace dataset; as it uses a CNN, no database is needed. You can optionally specify start and end offsets (for both training and testing); otherwise, the last 60 seconds of each trace will be used.
Note that features must be extracted before the attack can proceed. Use the `--extract` option when running for the first time on a dataset, which saves to `FEATURE_PATH`.

The attacks can be run in the following way from the `attacks` directory:
 - Leaky Streams: `python3 leaky.py attack ../tests/compare/db_leaky.txt <path to trace dataset>`
 - Walls Have Ears: `python3 walls.py attack ../tests/compare/db_walls.txt <path to trace dataset>`
 - Beauty and the Burst: `python3 beauty.py <path to trace dataset> --extract`

Additional, less noteworthy attack-specific options are available (loose range search for Leaky Streams and increased verbosity); run a script with the `--help` argument for more information.

### Defenses

Compilation with `cargo build --release` in the `defenses` directory will produce four binaries in `target/release`, one for each defense implementation. They generate machines based on supplied parameters.

Specifically, the binaries can be run as follows:
 - Constant: `./target/release/constant [send interval = 4000.0]`
 - Adapted FRONT: `./target/release/adapted_front <padding window> <padding budget> <num states>`
 - Adapted RegulaTor: `./target/release/adapted_regulator <initial rate> <decay rate> <upload ratio> <packets per state>`
 - Scrambler: `./target/release/scrambler <send interval> <minimum count> <min trail> <max trail>`

### Tests

Some simple tests to ensure that the code runs as expected are included under the `tests` directory.

The `test_attacks.sh` script takes one argument, which is the root path of the _trace_ dataset to test on (i.e. download the _LongEnough_ dataset, extract it, and pass in a path to the resulting directory, which should contain 100 subdirectories corresponding to the videos in the dataset).
It executes each attack in turn, and the test succeeds if they all run to completion without any errors. Expect this to take around 90 minutes, or much longer if you don't have a CUDA-supported GPU.

The `test_defenses.sh` script compiles and runs the defense code to generate Maybenot machines for all of the defense configurations presented in the paper - the test will succeed if the output is correct. This test should take a matter of minutes with a reasonable Internet connection, and it will be even faster if the defense code is already compiled.

For informational purposes: These tests rely on data included in the subdirectory `compare`. It contains database files for the Leaky
Streams and Walls Have Ears attacks, created using the _LongEnough_ dataset, as well as the serialized machine(s)
for each defense configuration presented in the paper. You do not need to touch this directory to run the tests.

## Datasets

As described in the paper, we provide the _LongEnough_ dataset, which contains traffic traces and QoE metric data for undefended streams, defended streams, and variable bandwidth conditions.

It is available here: [https://liuonline-my.sharepoint.com/:f:/g/personal/davha914_student_liu_se/ErK6esYd5IdOiuvfLnXK6NoBEdlj579MlXBvG2wkfQEozg?e=sCHtWp](https://liuonline-my.sharepoint.com/:f:/g/personal/davha914_student_liu_se/ErK6esYd5IdOiuvfLnXK6NoBEdlj579MlXBvG2wkfQEozg?e=sCHtWp)

More details are provided in the dataset README. The dataset contains the following files:

| File                    | Size                       |
| :---------------------- | :------------------------- |
| LongEnough.zip							   | (18G zipped, 81G expanded) |
| LongEnough-defended.zip	|	(16G zipped, 71G expanded) |
| LongEnough-variable.zip	|	(21G zipped, 83G expanded) |

## License Info

The code in this repository is available under the terms of the BSD-3-Clause license.

## References
 [1] Andrew Reed and Benjamin Klimkowski. "Leaky Streams: Identifying Variable Bitrate DASH Videos Streamed over Encrypted 802.11n Connections". IEEE Annual Consumer Communications & Networking Conference (CCNC). January 2016. (https://www.zenodo.org/record/1265584/files/article.pdf)  
 [2] Jiaxi Gu, Jiliang Wang, Zhiwen Yu, and Kele Shen. "Walls Have Ears: Traffic-based Side-channel Attack in Video Streaming". IEEE Conference on Computer Communications (INFOCOM). April 2018. (http://tns.thss.tsinghua.edu.cn/~jiliang/publications/INFOCOM2018-walls.pdf)  
 [3] Roei Schuster, Vitaly Shmatikov, and Eran Tromer. "Beauty and the Burst: Remote Identification of Encrypted Video Streams". USENIX Security. August 2017. (https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/schuster)  
 [4] Jiajun Gong and Tao Wang. "Zero-delay Lightweight Defenses against Website Fingerprinting". USENIX Security. August 2020. (https://www.usenix.org/conference/usenixsecurity20/presentation/gong)  
 [5] James Holland and Nicholas Hopper. "RegulaTor: A Straightforward Website Fingerprinting Defense". Proceedings on Privacy Enhancing Technologies (PoPETs), volume 2, 2022. (https://petsymposium.org/popets/2022/popets-2022-0049.php)  
 [6] Tobias Pulls and Ethan Witwer. "Maybenot: A Framework for Traffic Analysis Defenses". Workshop on Privacy in the Electronic Society (WPES). November 2023. (https://doi.org/10.1145/3603216.3624953)
 
