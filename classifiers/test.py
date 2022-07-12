import argparse
import joblib
import h5py
import os
import tensorflow.compat.v1 as tf
import time
import parallelpcap
from pcaps.features import load_features
from plot.plot import plot_pr, plot_roc
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (roc_auc_score, confusion_matrix, f1_score,
 average_precision_score, auc, precision_recall_curve, roc_curve)
from sklearn.kernel_approximation import RBFSampler

def test_classifier(output_dir, data_dir, test_data, classifier, labelfile, 
          dataset, debug, num_threads=1):
  """
  Tests binary classifiers on a set of raw pcaps.

  Parameters
  ----------
  output_dir : str
    Path to the output directory where the report will be stored
  data_dir : str
    Path to the working data directory where the dictionary and 
    embeddings are stored
  test_data : str
    Path to directory containing raw pcap test set
  classifier : str
    Path to saved classifier joblib file
  labelfile : str
    Path to groundtruth csv file
  dataset : str
    The dataset type.
  debug : bool
    Whether we should set debug on in c++ code.
  num_threads : int
    Number of threads ParallelPcap will use when creating feature
    vectors
  """
  classifier_type = classifier.split('/')[-1].split('.')[0]
  report_file = os.path.join(output_dir, '{}_test_report.txt'.format(classifier_type))

  # Report file
  report = open(report_file, 'w')
  report.write("===TEST REPORT===\n")

  # All predictions
  all_predictions = []

  # All labels
  all_labels = []

  # All binary predictions
  all_bin_preds = []

  parallelpcap.setParallelPcapThreads(num_threads)

  # Loading the embeddings
  final_embeddings = load_features(data_dir)

  # Loading the classifier
  clf = joblib.load(classifier)

  # Loading the dictionary
  if dataset == "isot":
    testpcap = parallelpcap.TestPcap_ISOT(os.path.join(data_dir, 
                     'dict/dictionary.bin'), 
                     final_embeddings, [2], labelfile, debug)
  elif dataset == "darpa2009":
    testpcap = parallelpcap.TestPcap_DARPA2009(os.path.join(data_dir, 
                     'dict/dictionary.bin'), 
                     final_embeddings, [2], labelfile, debug)

  test_files = [os.path.join(test_data, f) for f in os.listdir(test_data)]

  for i, f in enumerate(test_files):
    if (i + 1) % 10 == 0:
      print("Testing on file {} of {}".format(i + 1, len(test_files)))
    
    # Grab data
    X = testpcap.featureVector(f)
    y = testpcap.labelVector()

    if len(X) > 0:

      y_hat = clf.predict_proba(X)[:,1]
      y_hat_bin = clf.predict(X)

      tn, fp, fn, tp = confusion_matrix(y, y_hat_bin, labels=[0,1]).ravel()
      report.write("File: " + str(f) + "\n")
      report.write("Confusion Matrix (TN, FP, FN, TP): " + str(tn) + " " + 
             str(fp) + " " + str(fn) + " " + str(tp) + "\n")

      if 1 in y:
        scores = roc_auc_score(y, y_hat)
        f1 = f1_score(y, y_hat_bin)
        precision, recall, thresholds = precision_recall_curve(y, y_hat)
        ave_precision = average_precision_score(y, y_hat)
        pr_auc = auc(recall, precision)
        print("ROC AUC Score: ", scores)
        print("Precision/Recall AUC Score: ", pr_auc)
        print("Average precision: ", ave_precision) 
        print("F1 Score: ", f1)
        report.write("ROC AUC Score: " + str(scores) + "\n")
        report.write("F1 Score: " + str(f1) + "\n")
        report.write("Precision/Recall AUC Score: " + str(pr_auc) + "\n")
        report.write("Average precision: " + str(ave_precision) + "\n")
      else:
        print("No negative examples.")

      report.write("========\n")

      all_predictions.extend(y_hat)
      all_labels.extend(y)
      all_bin_preds.extend(y_hat_bin)
    else:
     print("Nothing in file.")

  all_roc_auc_score = roc_auc_score(all_labels, all_predictions)
  precision, recall, thresholds = precision_recall_curve(all_labels, 
                              all_predictions)
  all_pr_auc = auc(recall, precision)
  all_average_precision = average_precision_score(all_labels, all_predictions)
  all_f1 = f1_score(all_labels, all_bin_preds)
  print("Overall ROC AUC Score: ", all_roc_auc_score)
  print("Overall Precision/Recall AUC Score: ", all_pr_auc)
  print("Overall average precision: ", all_average_precision)
  print("Overall f1 score: ", all_f1)

  tn, fp, fn, tp = confusion_matrix(all_labels, all_bin_preds, 
                    labels=[0,1]).ravel()
  print("Overall TN, FP, FN, TP: ", tn, fp, fn, tp)

  report.write("Overall ROC AUC Score: " + str(all_roc_auc_score) + "\n")
  report.write("Overall Precision/Recall AUC Score: " + str(all_pr_auc) +"\n")
  report.write("Overall average precision: " + str(all_average_precision) +"\n")
  report.write("Overall f1 score: " + str(all_f1) + "\n")
  report.write("Overall TN, FP, FN, TP: " +str(tn) + " " + str(fp) + " "
    + str(fn) + " " +str(tp) +" \n")
  report.close()

  # Make plots
  plot_path = os.path.join(output_dir, 'plots')
  if not os.path.isdir(plot_path):
    os.makedirs(plot_path)
  
  roc_plot = os.path.join(plot_path, classifier_type + '_roc.png')
  pr_plot = os.path.join(plot_path, classifier_type + '_pr.png')
  
  plot_roc(roc_plot, all_labels, all_predictions)
  plot_pr(pr_plot, all_labels, all_predictions)

  joblib.dump(all_labels, os.path.join(output_dir, "y_true.joblib"))
  joblib.dump(all_predictions, os.path.join(output_dir, "y_score.joblib"))
