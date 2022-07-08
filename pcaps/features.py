import parallelpcap
import os
import re
import h5py
import datetime 
import tensorflow.compat.v1 as tf
from common import natural_keys, check_path

def load_features(data_dir):
  """
  Loads the embedding space from the saved 
  Word2Vec model.

  Parameters
  ----------
  data_dir : str
    Path to the token vectors and Word2Vec model
  """
  save_dir = os.path.join(data_dir, 'embeddings_model')
  print("save_dir", save_dir)

  # Loading the embeddings
  with tf.device('/cpu:0'):
    graph = tf.Graph()
    with graph.as_default():
      new_saver = tf.train.import_meta_graph(os.path.join(save_dir, 
                                            'embeddings_model.meta'))
      embeddings = graph.get_tensor_by_name('embeddings:0')
      norm = graph.get_tensor_by_name('norm:0')
      print("type embeddings", type(embeddings), "shape", embeddings.shape)
      print("type norm", type(norm), "shape", norm.shape)
      normalized_embeddings = embeddings / norm
      #=======
      # Loading the embeddings
      #with tf.device('/cpu:0'):
      #    graph = tf.Graph()
      #    with graph.as_default():
      #        new_saver = tf.train.import_meta_graph(os.path.join(save_dir, 
      #          'embeddings_model.meta'))
      #        embeddings = graph.get_tensor_by_name('embeddings:0')
      #        norm = graph.get_tensor_by_name('norm:0')
      #        normalized_embeddings = embeddings / norm
      #>>>>>>> origin/master

      with tf.Session(graph=graph) as session:
        new_saver.restore(session, tf.train.latest_checkpoint(save_dir))
        final_embeddings = normalized_embeddings.eval(session=session)

        return final_embeddings

def finalize_feature_vectors(output_dir, data_dir, dataset, labels):
  """
  Imports the saved Word2Vec model and 
  translates the token vectors to feature
  vectors using the embedded space.

  Parameters
  ----------
  output_dir : str
    Path to the output for the feature vectors
  data_dir : str
    Path to the token vectors and Word2Vec model
  dataset : str
    Dataset type (either "isot" or "darpa2009")
  labels : str
    Path to the groundtruth file with labels.
  """
 
  check_path(output_dir)
  check_path(data_dir)
  check_path(labels)

  final_embeddings = load_features(data_dir)

  if dataset == "isot":
    p2v = parallelpcap.Packet2Vec_ISOT(final_embeddings, labels, False)
  elif dataset == "darpa2009":
    p2v = parallelpcap.Packet2Vec_DARPA2009(final_embeddings, labels, False)
  else:
    raise Exception(f"Unknown dataset class: {dataset}")

  intVV = os.path.join(data_dir, 'intVectorVector')
  check_path(intVV)
  pcaps = os.path.join(data_dir, 'pcaps')
  check_path(pcaps)
  feature_dir = os.path.join(output_dir, 'features')
  if not os.path.isdir(feature_dir):
    os.makedirs(feature_dir)
  
  token_files = os.listdir(intVV)
  for token_file in token_files:
    pcap_filename = '_'.join(token_file.split('_')[1:])
    pcap_id = '.'.join(pcap_filename.split('.')[0:-1])

    print("token_file", token_file)
    print("pcap_filename", pcap_filename)
    print("pcap_id", pcap_id)
    print("pcaps", pcaps)
    X = p2v.generateX(os.path.join(intVV, token_file))

    pcap_path = os.path.join(pcaps, pcap_filename)
    print(pcap_path)
    if not os.path.exists(pcap_path):
      raise FileNotFoundError(f"Path to pcap file {pcap_path}" +
                              " does not exist")
    y = p2v.generateY(pcap_path)


    feature_filename = os.path.join(feature_dir, pcap_id + '_features.h5')
    h5f = h5py.File(feature_filename, 'w')
    h5f.create_dataset('vectors', data=X)
    h5f.create_dataset('labels', data=y)
    h5f.close()

