# An implementation of Walls Have Ears: Traffic-based Side-channel Attack in
# Video Streaming (Jiaxi Gu, Jiliang Wang, Zhiwen Yu, Kele Shen).
# Code from the paper: David Hasselquist, Ethan Witwer, August Carlson, Niklas
# Johansson, and Niklas Carlsson. "Raising the Bar: Improved Fingerprinting
# Attacks and Defenses for Video Streaming Traffic". Proceedings on Privacy
# Enhancing Technologies (PoPETs), volume 4, 2024.
# If you use this code in your work, please include a reference to both papers.
# More details are available in README.md

import argparse
import ast
import math
import os


NUM_CLASSES = 100

# number of segments in fingerprint
FINGERPRINT_SIZE = 45

# These are used for Algorithm 1 in the paper
EPS = 20000 # 20 kB, from paper
TAU = 1     # L / 2, from paper


# Evaluate the Sigmoid function on input
def sigmoid(x):
  return (math.e ** x) / (1 + math.e ** x)


# Normalize a sequence by applying the Sigmoid function
def normalize(seq):
  for i in range(len(seq)):
    seq[i] = sigmoid(seq[i])


# Get the sequence of segment sizes for a video.
# You can specify "" for quality to consider everything.
# For this attack, since it uses differentials, only one
# quality should be needed and it probably doesn't matter
# which (c.f. Figure 9 WHE). Default is thus 4000 kbit/s.
def get_segment_sizes(dataset_root, video_id, quality = "4000"):
  path = os.path.join(dataset_root, f"{(video_id + 1):03}", "segments")
  
  segments = [file for file in os.listdir(path) if f"video_{quality}" in file and "m4s" in file]
  segments = sorted(segments, key = lambda file: int(file.split("_")[2].split(".")[0]))
  
  sizes = [float(os.path.getsize(os.path.join(path, file))) for file in segments][-FINGERPRINT_SIZE:]
  
  return sizes


# Compute the fingerprint for a video in the dataset.
def compute_fingerprint(dataset_root, video_id):
  sizes = get_segment_sizes(dataset_root, video_id)
  
  diffs = [0]
  for i in range(1, len(sizes)):
    diffs.append((sizes[i] - sizes[i - 1]) / sizes[i - 1])
  
  return diffs


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
    normalize(database[video])
  
  save_fingerprints(database, path)


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
    offset = timestamp - (last_time - start)
    
    while len(bw) <= offset:
      bw.append(0)
    
    bw[math.floor(offset)] += size
  
  # Ensure length corresponds to [start, end)
  while len(bw) < start - end:
    bw.append(0)
  
  return bw


# Get the data amount per period from a trace.
# This corresponds to Algorithm 1 in the paper.
def aggregate_traffic(bw, start, end):
  periods = [0] * math.ceil((start - end) / 2)
  
  index = 0
  segstart = len(bw) - 1
  
  for time in range(len(bw) - 1, -1, -1):
    if bw[time] < EPS:
      continue
    
    if segstart - time + 1 > TAU and periods[index] > 0:
      index += 1
      segstart = time - 1
    
    if index >= len(periods):
      break
    periods[index] += bw[time]
  
  periods.reverse()
  while periods[0] == 0:
    periods = periods[1:]
    periods.append(0)
  return periods


# Compute the differentials between periods.
# This is essentially Equation 4 in the paper.
def calc_differentials(periods):
  diffs = [0]

  for i in range(1, len(periods)):
    diffs.append((periods[i] - periods[i - 1]) / periods[i - 1])
  
  return diffs


# Calculate sequence similarity with P-DTW.
def calc_similarity(template, query):
  distances = []
  
  for a in range(0, len(template)):
    for b in range(0, len(template)):
      subseq = template[a:(b + 1)]
      if len(subseq) != len(query):
        continue
      
      n = len(query)
      m = len(subseq)
      
      M = []
      for _ in range(0, n + 1):
        M.append([0.0] * (m + 1))
      
      for i in range(1, n + 1):
        M[i][0] = math.inf
      for i in range(1, m + 1):
        M[0][i] = math.inf
      
      for i in range(1, n + 1):
        for j in range(1, m + 1):
          cost = abs(query[i - 1] - subseq[j - 1])
          if j >= 2:
            min_factor = min(M[i - 1][j], M[i - 1][j - 1], M[i - 1][j - 2])
          else:
            min_factor = min(M[i - 1][j], M[i - 1][j - 1])
          M[i][j] = cost + min_factor
      
      distances.append(M[n][m] / n)
  
  return min(distances)


# Run the attack for a given trace and observation period.
def perform_attack(database, trace_file, start, end, verbose = False):
  bw = get_throughput(trace_file, start, end)
  periods = aggregate_traffic(bw, start, end)
  diffs = calc_differentials(periods)
  normalize(diffs)
  
  closest = None
  distance = math.inf
  
  for video in database.keys():
    curr_dist = calc_similarity(database[video], diffs)
    
    if curr_dist <= distance:
      closest = video
      distance = curr_dist
  
  if verbose:
    print(f"Closest match is {closest}, with distance {distance}")
  
  return (closest, distance)


# Run the attack for all traces in a trace dataset.
def attack_all(database, trace_root, start, end, verbose = False):
  total_correct = 0
  total_predictions = 0
  per_video = [(0, 0)] * NUM_CLASSES
  
  # Do comparisons
  for video in range(NUM_CLASSES):
    video_root = os.path.join(trace_root, str(video))
    all_traces = [file for file in os.listdir(video_root) if ".sim.log" in file or (".log" in file and file.count(".") == 1)]
    
    for trace in all_traces:
      result = perform_attack(database, os.path.join(video_root, trace), start, end)
      
      if result[0] == video:
        if verbose:
          print(f"Correct classification, {result}")
        
        correct, predictions = per_video[video]
        per_video[video] = (correct + 1, predictions + 1)
        total_correct += 1
      else:
        if verbose:
          print(f"Incorrect classification, {video} -> {result}")
        
        correct, predictions = per_video[video]
        per_video[video] = (correct, predictions + 1)
      total_predictions += 1
  
  # Print per-video accuracy
  if verbose:
    print("\n\n")
  
  for video in range(NUM_CLASSES):
    correct, predictions = per_video[video]
    if predictions == 0:
      continue
    
    print(f"Video {video:02} --- {correct}/{predictions} ({correct / predictions * 100}%)")
  
  # Print global accuracy
  print(f"Global accuracy {total_correct}/{total_predictions} ({total_correct / total_predictions * 100}%)")


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser = argparse.ArgumentParser()
  parser.add_argument("mode", help = "setup or attack", choices = ["setup", "attack"])
  parser.add_argument("database", help = "path to database file, save (setup) or load (attack)")
  parser.add_argument("target", help = "path to segment size dataset (setup) or trace dataset (attack)")
  parser.add_argument("-s", "--start", help = "eavesdropping start time, in seconds from end of trace", type = int, default = 60)
  parser.add_argument("-e", "--end", help = "eavesdropping end time, in seconds from end of trace", type = int, default = 0)
  parser.add_argument("--verbose", help = "verbose output", action = "store_true")
  args = parser.parse_args()
  
  if args.mode == "setup":
    setup_database(args.database, args.target)
  else: # attack
    database = load_fingerprints(args.database)
    attack_all(database, args.target, args.start, args.end, args.verbose)
