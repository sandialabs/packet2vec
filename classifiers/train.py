import argparse
import joblib
import h5py
import time
import os
import numpy as np

from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import SGDClassifier
from sklearn.kernel_approximation import RBFSampler
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils.class_weight import compute_class_weight

def train_step(clf, X, y, trained_once, found, n_estimators):

  non_zeros = np.count_nonzero(y)
  zeros = y.size - non_zeros
  if non_zeros > 0:
    found = True
  print(f"Shape X {X.shape}")
  print(f"Shape y {y.shape}")
  print(f"Number of 0's: {zeros}")
  print(f"Number of 1's: {non_zeros}")
   
  if trained_once:
      clf.n_estimators += n_estimators

  clf.fit(X, y)
  return clf, found


def randomForestClassifier(data, output_dir, n_estimators=10, 
                           max_examples=100000):
    """
    Trains a Random Forest classifier on the data 
    generated in the 'features' step.

    Parameters
    ----------
    data : str
        Path to the working data directory containing the features
    output_dir : str
        Path to the output directory where the models are stored
    n_estimators : int
        Number of estimators to add to the forest on each iteration
    """
    # Grab list of files
    features = os.path.join(data, 'features')
    feature_files = [os.path.join(features, f) for f in os.listdir(features)]
    
    clf = RandomForestClassifier(warm_start=True,
                                 n_estimators=n_estimators)

    found = False
    trained_once = False
    data_not_utilized = False

    X = None
    y = None

    i = 0 
    while i < len(feature_files):

        if X is None:
            with h5py.File(feature_files[0], 'r') as hf:
                X = np.zeros((0, hf['vectors'][:].shape[1]))
                y = np.zeros((0,))

        print(f"Processing file {feature_files[i]}")
        with h5py.File(feature_files[i], 'r') as hf:
            X1 = hf['vectors'][:]
            y1 = hf['labels'][:]
            X = np.concatenate((X, X1))
            y = np.concatenate((y, y1))
            print(f"Shape X {X.shape}")
            print(f"Shape y {y.shape}")
            #non_zeros = np.count_nonzero(y1)
            #zeros = y.size - non_zeros
            #if non_zeros > 0:
            #  found = True
            #print(f"Shape X1 {X1.shape}")
            #print(f"Shape y1 {y1.shape}")
            #print(f"Number of 0's: {zeros}")
            #print(f"Number of 1's: {non_zeros}")

        if len(X) > max_examples:
            clf, found = train_step(clf, X, y, trained_once, found, n_estimators)
            trained_once = True
            data_not_utilized = False
            X = None
            y = None
        else:
            data_not_utilized = True

        i += 1
    
    if data_not_utilized:
      clf, found = train_step(clf, X, y, trained_once, found, n_estimators)

        

    """
    for i, f in enumerate(feature_files):
        print("Training RFC on file {} of {}".format(i + 1, len(feature_files)))
        
        with h5py.File(f, 'r') as hf:
             
            X = hf['vectors'][:]
            y = hf['labels'][:]
            print(X.shape)
            print(y.shape)

        zeros = np.count_nonzero(y)
        non_zeros = y.size - zeros
        print(f"Number of 0's: {zeros}")
        print(f"Number of 1's: {non_zeros}")

        # Ignore files where there are no 
        # malicious samples
        if 1 not in y:
          print("Skipping this file because no malicious examples.") 
          continue
        else:
          found = True

        if i != 0:
            clf.n_estimators += n_estimators
        
        clf.fit(X, y)
    """

    if not found:
      raise Exception("Didn't find any malicious examples in the training" +
        " data")

    output_path = os.path.join(output_dir, 'classifiers')
    if not os.path.isdir(output_path):
        os.makedirs(output_path)

    joblib.dump(clf, os.path.join(output_path, 'rfc.joblib'))

def scan_for_start(feature_files):
    """
    Scans the list of feature files looking for
    the first instance of a file containing positive
    samples. This must be done because we can't initiate
    training without both classes present.

    Parameters
    ----------
    feature_files : str
        Path to the directory containing the feature files
    """
    for i, f in enumerate(feature_files):
        with h5py.File(f, 'r') as hf:
            y = hf['labels'][:]
            if 1 in y: return i
  
    return -1

def naiveBayesClassifier(data, output_dir):
    """
    Trains a Naive Bayes classifier on the data 
    generated in the 'features' step.

    Parameters
    ----------
    data : str
        Path to the working data directory containing the features
    output_dir : str
        Path to the output directory where the models are stored
    """
    # Grab list of files
    features = os.path.join(data, 'features')
    feature_files = [os.path.join(features, f) for f in os.listdir(features)]

    clf = GaussianNB()
    starting_index = scan_for_start(feature_files)
    
    with h5py.File(feature_files[starting_index], 'r') as hf:
        X = hf['vectors'][:]
        y = hf['labels'][:]
        
        clf.fit(X, y)
        # Delete from list so we dont train on it again
        del feature_files[starting_index]
    
    for i, f in enumerate(feature_files):
        if (i + 1) % 10 == 0:
            print("Training GNB on file {} of {}".format(i + 1, len(feature_files) + 1))
        
        with h5py.File(f, 'r') as hf:
            X = hf['vectors'][:]
            y = hf['labels'][:]

            clf.partial_fit(X, y)

    output_path = os.path.join(output_dir, 'classifiers')
    if not os.path.isdir(output_path):
        os.makedirs(output_path)

    joblib.dump(clf, os.path.join(output_path, 'gnb.joblib'))
