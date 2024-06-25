# An implementation of Leaky Streams: Identifying Variable Bitrate DASH Videos
# Streamed over Encrypted 802.11n Connections (Andrew Reed, Benjamin Klimkowski).
# Code from the paper: David Hasselquist, Ethan Witwer, August Carlson, Niklas
# Johansson, and Niklas Carlsson. "Raising the Bar: Improved Fingerprinting
# Attacks and Defenses for Video Streaming Traffic". Proceedings on Privacy
# Enhancing Technologies (PoPETs), volume 4, 2024.
# If you use this code in your work, please include a reference to both papers.
# More details are available in README.md

import argparse
import ast
import itertools
import math
import numpy as np
import os

from kdtree import KdTree
from kdtree.point import Point


NUM_CLASSES = 100

# number of segments in fingerprint
FINGERPRINT_SIZE = 45

# anything greater is considered a match
CORRELATION_THRESH = 0.9

# used for k-d tree range search bounds
# T1: dim. 1 (total size), T2: dim. 2-6
T1_LOOSE = 0.1
T2_LOOSE = 0.03

T1_TIGHT = 0.07
T2_TIGHT = 0.03


# Get the sequence of segment sizes for a video.
# You can specify "" for quality to consider everything.
def get_segment_sizes(dataset_root, video_id, quality = "4000"):
  path = os.path.join(dataset_root, f"{(video_id + 1):03}", "segments")
  
  segments = [file for file in os.listdir(path) if f"video_{quality}" in file and "m4s" in file]
  segments = sorted(segments, key = lambda file: int(file.split("_")[2].split(".")[0]))
  
  sizes = [float(os.path.getsize(os.path.join(path, file))) for file in segments][-FINGERPRINT_SIZE:]
  
  return sizes


# Compute the fingerprint for a video in the dataset.
# This consists of three sequences of segment sizes, one for each quality level.
def compute_fingerprint(dataset_root, video_id):
  sizes1k = get_segment_sizes(dataset_root, video_id, "1000")
  sizes2k = get_segment_sizes(dataset_root, video_id, "2000")
  sizes4k = get_segment_sizes(dataset_root, video_id, "4000")
  
  return (sizes1k, sizes2k, sizes4k)


# Save a dictionary of video IDs/fingerprints to a file.
def save_fingerprints(database, path):
  with open(path, "w") as f:
    for video_id in database.keys():
      f.write(f"{video_id:02}\t{database[video_id]}\n")


# Load a dictionary of video IDs/fingerprints from a file.
def load_fingerprints(path):
  database = {}
  
  with open(path) as f:
    for line in f:
      tokens = line.split("\t")
      
      if len(tokens) != 2:
        continue
      
      # Propagate exceptions
      video_id = int(tokens[0])
      fingerprint = ast.literal_eval(tokens[1])
      
      database[video_id] = fingerprint
  
  return database


# Compute fingerprints for every video and save them.
def setup_database(path, dataset_root):
  database = {}
  
  for video in range(NUM_CLASSES):
    database[video] = compute_fingerprint(dataset_root, video)
  
  save_fingerprints(database, path)


# Calculate the k-d tree key for a window of 30 segments.
def calculate_key(window):
  # dim 1: total data in window
  total_size = sum(window)
  
  # dim 2-6: divide into six-segment slices
  dim2 = sum(window[:6]) / total_size
  dim3 = sum(window[6:12]) / total_size
  dim4 = sum(window[12:18]) / total_size
  dim5 = sum(window[18:24]) / total_size
  dim6 = sum(window[24:]) / total_size
  
  return (total_size, dim2, dim3, dim4, dim5, dim6)


# Construct a k-d tree given a database of fingerprints.
def build_kdtree(database):
  data = [] # 48 data points per video
  metadata = {}
  
  for video in database.keys():
    for quality in range(3):                        # index in video tuple
      for offset in range(FINGERPRINT_SIZE - 29):   # sliding window start
        window = database[video][quality][offset:(offset + 30)]
        key = calculate_key(window)
        
        data.append(Point(list(key)))
        metadata[key] = (video, quality, offset)
  
  return KdTree(6, data), metadata


# Get the last time from a trace.
# Round up to nearest two seconds.
def get_last_time(lines):
  for line in reversed(lines):
    tokens = line.split(",")

    if len(tokens) < 2:
      continue

    if "r" == tokens[1] or "r+p" == tokens[1] or "s" == tokens[1] or "s+p" == tokens[1]:
      last_time = int(tokens[0]) / 1000000000
      last_time = math.ceil(last_time / 2) * 2
      return last_time
  
  return -1


# Get the throughput per two seconds from a trace.
# Specify eavesdropping period with start and end.
def get_throughput(trace_file, start, end):
  bw = []
  
  with open(trace_file) as f:
    lines = f.readlines()
  last_time = get_last_time(lines)
  
  for line in lines:
    tokens = line.split(",")
    if len(tokens) < 3:
      continue
    timestamp = int(tokens[0]) / 1000000000
    direction = tokens[1]
    size = int(tokens[2])
    
    # Constrain the eavesdropping period
    if timestamp < last_time - start:
      continue
    if timestamp >= last_time - end:
      break
    
    # Only considering server-to-client traffic
    if "r" not in direction:
      continue
    
    # Create a new bin or add to an existing one
    offset = (timestamp - (last_time - start)) / 2.0
    
    while len(bw) <= offset:
      bw.append(0)
    
    bw[math.floor(offset)] += size
  
  # Account for lower-layer header overhead
  for i in range(len(bw)):
    bw[i] *= 1460.0 / 1500.0
  
  # Ensure length corresponds to [start, end)
  offset = (start - end) / 2.0
  
  while len(bw) < offset:
    bw.append(0)
  
  return bw


# Run the attack for a given trace and observation period.
def perform_attack(database, kdtree, metadata, trace_file, start, end, loose = False, verbose = False):
  bw = get_throughput(trace_file, start, end)
  
  if loose:
    T1 = T1_LOOSE
    T2 = T2_LOOSE
  else:
    T1 = T1_TIGHT
    T2 = T2_TIGHT
  
  matches = []
  counts = [0] * NUM_CLASSES # matches per candidate video
  
  for offset in range(len(bw) - 29):
    capture = bw[offset:(offset + 30)]
    key = calculate_key(capture)
    
    # Stage 1: retrieve candidate windows
    margin = (T1 * key[0], T2 * key[1], T2 * key[2], T2 * key[3], T2 * key[4], T2 * key[5])
    bounds = [[key[i] - margin[i], key[i] + margin[i]] for i in range(6)]
    candidate_keys = kdtree.get_points_within_bounds(bounds)
    
    # Stage 2: report matching windows
    for candidate_key in candidate_keys:
      candidate_video, candidate_quality, candidate_offset = metadata[tuple(candidate_key)]

      capture_copy = capture.copy()
      candidate = database[candidate_video][candidate_quality][candidate_offset:(candidate_offset + 30)]
      
      # -- ignore four outliers
      diffs = [(abs((candidate[i] - capture_copy[i]) / capture_copy[i]), i) for i in range(30)]
      diffs.sort()
      
      outliers = [segment for _, segment in diffs[-4:]]
      outliers.sort(reverse = True)
      
      for segment in outliers:
        del capture_copy[segment]
        del candidate[segment]
      
      # -- calculate Pearson's correlation
      corrcoef = np.corrcoef(capture_copy, candidate)[0][1]
      
      if corrcoef > CORRELATION_THRESH:
        matches.append((candidate_video, candidate_offset, offset))
        counts[candidate_video] += 1
        
        # Stage 3a: determine video from reported matches, fast mode
        for pair in itertools.combinations(range(0, len(matches)), 2):
          match1 = matches[pair[0]]
          match2 = matches[pair[1]]
          
          if match1[0] != match2[0]:
            continue
          video = match1[0]
          
          if abs(match1[1] - match2[1]) >= 5 and abs(match1[1] - match2[1]) == abs(match1[2] - match2[2]):
            if verbose:
               print(f"Fast mode classification, {video}")
               print(f"Match 1: {match1}")
               print(f"Match 2: {match2}")
            
            return video, True
  
  # Stage 3b: determine video from reported matches, slow mode
  max_count = max(counts)
  video = counts.index(max_count)
  
  if verbose:
    print(f"Slow mode classification, {video}")
    print(f"Count: {max_count}")
  
  return video, False


# Run the attack for all traces in a trace dataset.
def attack_all(database, trace_root, start, end, loose = False, verbose = False):
  total_correct = 0
  total_predictions = 0
  per_video = [(0, 0)] * NUM_CLASSES
  
  fast_right = 0
  fast_wrong = 0
  
  slow_right = 0
  slow_wrong = 0
  
  # Set up k-d tree
  kdtree, metadata = build_kdtree(database)
  
  # Do comparisons
  for video in range(NUM_CLASSES):
    video_root = os.path.join(trace_root, str(video))
    all_traces = [file for file in os.listdir(video_root) if ".sim.log" in file or (".log" in file and file.count(".") == 1)]
    
    for trace in all_traces:
      result = perform_attack(database, kdtree, metadata, os.path.join(video_root, trace), start, end, loose, verbose)
      
      if result[0] == video:
        if verbose:
          print(f"Correct classification, {result}\n")
        
        correct, predictions = per_video[video]
        per_video[video] = (correct + 1, predictions + 1)
        total_correct += 1
        
        if result[1]:
          fast_right += 1
        else:
          slow_right += 1
      else:
        if verbose:
          print(f"Incorrect classification, {video} -> {result}\n")
        
        correct, predictions = per_video[video]
        per_video[video] = (correct, predictions + 1)
        
        if result[1]:
          fast_wrong += 1
        else:
          slow_wrong += 1
      total_predictions += 1
  
  # Print per-video accuracy
  if verbose:
    print("\n\n")
  
  for video in range(0, NUM_CLASSES):
    correct, predictions = per_video[video]
    if predictions == 0:
      continue
    
    print(f"Video {video:02} --- {correct}/{predictions} ({correct / predictions * 100}%)")
  
  # Print global accuracy
  print(f"Global accuracy {total_correct}/{total_predictions} ({total_correct / total_predictions * 100}%)")
  print(f"{fast_right} correct classifications were fast mode, {slow_right} were slow mode")
  print(f"{fast_wrong} wrong classifications were fast mode, {slow_wrong} were slow mode")


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument("mode", help = "setup or attack", choices = ["setup", "attack"])
  parser.add_argument("database", help = "path to database file, save (setup) or load (attack)")
  parser.add_argument("target", help = "path to segment size dataset (setup) or trace dataset (attack)")
  parser.add_argument("-s", "--start", help = "eavesdropping start time, in seconds from end of trace", type = int, default = 60)
  parser.add_argument("-e", "--end", help = "eavesdropping end time, in seconds from end of trace", type = int, default = 0)
  parser.add_argument("--loose", help = "use loose ranges for range search")
  parser.add_argument("--verbose", help = "verbose output", action = "store_true")
  args = parser.parse_args()
  
  if args.mode == "setup":
    setup_database(args.database, args.target)
  else: # attack
    database = load_fingerprints(args.database)
    attack_all(database, args.target, args.start, args.end, args.loose, args.verbose)
