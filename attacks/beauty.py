# An implementation of Beauty and the Burst: Remote Identification of Encrypted
# Video Streams (Roei Schuster, Vitaly Shmatikov, Eran Tromer).
# Code from the paper: David Hasselquist, Ethan Witwer, August Carlson, Niklas
# Johansson, and Niklas Carlsson. "Raising the Bar: Improved Fingerprinting
# Attacks and Defenses for Video Streaming Traffic". Proceedings on Privacy
# Enhancing Technologies (PoPETs), volume 4, 2024.
# If you use this code in your work, please include a reference to both papers.
# More details are available in README.md

import argparse
import ast
import math
import numpy as np
import os
import random
import statistics

from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation, Flatten
from keras.layers import Conv2D, MaxPooling2D


EPOCHS = 500
BATCH_SIZE = 64
NUM_CLASSES = 100

FEATURE_PATH = "features.txt"
FEATURES_USED = 3 # PPS, down/up/all


def build_model(num_classes):
  model = Sequential()
  
  model.add(Conv2D(32, (1, 16), data_format = "channels_first", activation = "relu"))
  model.add(Conv2D(32, (1, 16), data_format = "channels_first", activation = "relu"))
  model.add(Conv2D(32, (1, 16), data_format = "channels_first", activation = "relu"))
  model.add(Dropout(0.5))
  
  model.add(MaxPooling2D(pool_size = (1, 6), data_format = "channels_first"))
  model.add(Dropout(0.7))
  
  model.add(Flatten(data_format = "channels_first"))
  
  model.add(Dense(64, activation='relu'))
  model.add(Dropout(0.5))
  
  model.add(Dense(num_classes))
  model.add(Activation("softmax"))
  
  return model


# Get the last time from a trace.
# Round up to nearest two seconds.
def get_last_time(lines):
  for line in reversed(lines):
    tokens = line.split(",")

    if len(tokens) < 2:
      continue

    # Exclude trailing padding
    if "r" == tokens[1] or "r+p" == tokens[1] or "s" == tokens[1] or "s+p" == tokens[1]:
      last_time = int(tokens[0]) / 1000000000
      last_time = math.ceil(last_time / 2) * 2
      return last_time
  
  return -1


# Get packet count per 0.25 seconds from a trace.
# Specify eavesdropping period with start and end.
def get_packet_count(trace_file, direction, start, end):
  counts = []
  
  with open(trace_file) as f:
    lines = f.readlines()
  last_time = get_last_time(lines)
  
  for line in lines:
    tokens = line.split(",")
    if len(tokens) < 2:
      continue
    timestamp = int(tokens[0]) / 1000000000
    
    # Constrain the eavesdropping period
    if timestamp < last_time - start:
      continue
    if timestamp >= last_time - end:
      break
    
    # Only consider traffic in specified direction
    if direction not in tokens[1]:
      continue
    
    # Create a new bin or add to an existing one
    offset = (timestamp - (last_time - start)) * 4.0
    
    while len(counts) <= offset:
      counts.append(0)
    
    counts[math.floor(offset)] += 1
  
  # Ensure length corresponds to [start, end)
  offset = (start - end) * 4.0

  while len(counts) < offset:
    counts.append(0)
  
  return counts


# YouTube classifier, PPS features
# These will be saved to FEATURE_PATH
def extract_features(path, start, end):
  all_pairs = []
  
  max_pps_up = None
  max_pps_down = None
  max_pps_all = None
  
  for video in range(NUM_CLASSES):
    video_root = os.path.join(path, str(video))
    all_traces = [file for file in os.listdir(video_root) if ".sim.log" in file or (".log" in file and file.count(".") == 1)]
    
    for trace in all_traces:
      trace_file = os.path.join(video_root, trace)
      
      pps_up = get_packet_count(trace_file, "s", start, end)
      pps_down = get_packet_count(trace_file, "r", start, end)
      pps_all = [pps_up[i] + pps_down[i] for i in range(len(pps_up))]
      
      pps_up = [value / 0.25 for value in pps_up]
      pps_down = [value / 0.25 for value in pps_down]
      pps_all = [value / 0.25 for value in pps_all]
      
      # For normalization
      max_pps_up = max(max_pps_up, max(pps_up)) if max_pps_up else max(pps_up)
      max_pps_down = max(max_pps_down, max(pps_down)) if max_pps_down else max(pps_down)
      max_pps_all = max(max_pps_all, max(pps_all)) if max_pps_all else max(pps_all)
      
      labels = [0.0] * NUM_CLASSES
      labels[video] = 1.0
      
      all_pairs.append(([pps_down, pps_up, pps_all], labels))

  # Normalize on a per-feature basis
  for i in range(len(all_pairs)):
    for j in range((start - end) * 4):
      all_pairs[i][0][0][j] /= max_pps_down
      all_pairs[i][0][1][j] /= max_pps_up
      all_pairs[i][0][2][j] /= max_pps_all
  
  # Save features to file
  with open(FEATURE_PATH, "w") as f:
    f.write(f"{all_pairs}\n")


# Load from FEATURE_PATH
def load_features():
  with open(FEATURE_PATH) as f:
    lines = f.readlines()
  all_pairs = ast.literal_eval(lines[0])
  
  # 0.7/0.3 train-test split, as in paper
  random.shuffle(all_pairs)
  split = math.floor(len(all_pairs) * 0.7)

  train_x = [x for x, _ in all_pairs[:split]]
  train_y = [y for _, y in all_pairs[:split]]

  test_x = [x for x, _ in all_pairs[split:]]
  test_y = [y for _, y in all_pairs[split:]]
  
  for i in range(len(train_x)):
    train_x[i] = [train_x[i]]
  for i in range(len(test_x)):
    test_x[i] = [test_x[i]]
  
  return np.array(train_x), np.array(train_y), np.array(test_x), np.array(test_y)


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument("path", help = "trace dataset for use in attack")
  parser.add_argument("-s", "--start", help = "eavesdropping start time, in seconds from end of trace", type = int, default = 60)
  parser.add_argument("-e", "--end", help = "eavesdropping end time, in seconds from end of trace", type = int, default = 0)
  parser.add_argument("--extract", help = "extract features, required when running first time", action = "store_true")
  args = parser.parse_args()
  
  if args.extract:
    extract_features(args.path, args.start, args.end)
  
  model = build_model(NUM_CLASSES)
  model.compile(loss = "categorical_crossentropy", optimizer = "adam", metrics = ["accuracy"])

  all_train = []
  all_test = []

  for _ in range(5):
    train_x, train_y, test_x, test_y = load_features()
    model.fit(train_x, train_y, epochs = EPOCHS, batch_size = BATCH_SIZE)
    
    _, accuracy = model.evaluate(train_x, train_y)
    print(f"Train accuracy: {accuracy:.4f}")
    all_train.append(accuracy)
    
    _, accuracy = model.evaluate(test_x, test_y)
    print(f"Test accuracy: {accuracy:.4f}")
    all_test.append(accuracy)

  print(f"Overall train: {statistics.mean(all_train):.4f}")
  print(f"Overall test: {statistics.mean(all_test):.4f}")
