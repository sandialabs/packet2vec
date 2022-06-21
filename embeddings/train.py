import tensorflow.compat.v1 as tf
import numpy as np
import os
import struct
import embeddings.word2vec as w2v

def read_data(f):
    """
    Reads the integer tokens from a binary file
    saved on disk.

    Parameters
    ----------
    f : str
        Path to the binary file
    Returns
    -------
    integer_tokens : list
        List of integer tokens
    """
    integer_tokens = []

    with open(f, 'rb') as bf:
        while True:
            # Not sure if we want to read 8 bytes for every system
            data = bf.read(8)
            if not data: break
            s = struct.unpack('q', data)
            integer_tokens.append(s[0])

    return integer_tokens

def update(output_dir, load_dir, data_dir, vocab_size):
    """
    Update an existing Word2Vec model with new
    token vectors.

    Parameters
    ----------
    output_dir : str
        Path to the output directory where model will be saved
    load_dir : str
        Path to the saved model
    data_dir : str
        Path to the token vectors
    vocab_size : int
        Word2Vec vocab size
    """
    model_save_dir = os.path.join(output_dir, 'embeddings_model')
    if not os.path.isdir(model_save_dir):
        os.makedirs(model_save_dir)

    input_dir = os.path.join(data_dir, 'intVector')
    binary_files =  os.listdir(input_dir)

    finalRun = False
    firstRun = True
    for i, bf in enumerate(binary_files):
        if i == len(binary_files) - 1:
            finalRun = True

        bf = os.path.join(input_dir, bf)
        data = read_data(bf)

        if firstRun:
            final_embeddings = w2v.update_model(model_save_dir, data, load_dir, 
                                                vocab_size=vocab_size)
        else:
            final_embeddings = w2v.update_model(model_save_dir, data, 
                                                vocab_size=vocab_size)

        if finalRun: return final_embeddings
        firstRun = False

def create(output_dir, data_dir, vocab_size):
    """
    Create a new Word2Vec model with token
    vectors generated in the 'tokens' step.

    Parameters
    ----------
    output_dir : str
        Path to the output directory where model will be saved
    data_dir : str
        Path to the token vectors
    vocab_size : int
        Word2Vec vocab size
    """
    model_save_dir = os.path.join(output_dir, 'embeddings_model')
    if not os.path.isdir(model_save_dir):
        os.makedirs(model_save_dir)
    
    input_dir = os.path.join(data_dir, 'intVector')
    binary_files = os.listdir(input_dir)

    finalRun = False
    firstRun = True
    for i, bf in enumerate(binary_files):
        if i == len(binary_files) - 1:
            finalRun = True

        bf = os.path.join(input_dir, bf)
        data = read_data(bf)
        
        if firstRun:
            final_embeddings = w2v.new_model(model_save_dir, data, 
                                             vocab_size=vocab_size)
        else:
            final_embeddings = w2v.update_model(model_save_dir, data, 
                                                vocab_size=vocab_size)

        if finalRun: return final_embeddings
        firstRun = False
