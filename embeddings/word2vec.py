import tensorflow as tf
import numpy as np
import math
import os
from embeddings.helpers import is_batch_good, generate_batch
from six.moves import xrange

def update_model(save_dir, integer_tokens, load_dir='',
              batch_size=128, vocab_size=50000, 
              embedding_size=128, num_negative=64, 
              num_steps=100001, num_skips=2, skip_window=1):
    """
    Update an existing Word2Vec model with new
    token vectors.

    Parameters
    ----------
    save_dir : str
        Path to the output directory where model will be saved
    integer_tokens : str
        Path to the 1D token vectors
    load_dir : str
        Path to the previously trained model
    """
    # Handle loading a new model
    if load_dir == '':
        load_dir = save_dir

    # Create TF graph
    with tf.device('/gpu:0'):
        graph =  tf.Graph()
        with graph.as_default():
            with tf.device('/cpu:0'):
                # If we aren't on the first run, pull everything from checkpoint
                new_saver = tf.train.import_meta_graph(os.path.join(load_dir, 'embeddings_model.meta'))
                loss = graph.get_tensor_by_name('loss:0')
                train_inputs = graph.get_tensor_by_name('train_inputs:0')
                train_labels = graph.get_tensor_by_name('train_labels:0')
                embeddings = graph.get_tensor_by_name('embeddings:0')
                norm = graph.get_tensor_by_name('norm:0')
                normalized_embeddings = embeddings / norm

                saver = tf.train.Saver()
        with tf.Session(graph=graph) as session:
            new_saver.restore(session, tf.train.latest_checkpoint(load_dir))
            optimizer = tf.get_collection('optimizer')[0]
            
            data_index = 0
            average_loss = 0

            for step in xrange(num_steps):
                good_batch = False
                while not good_batch:
                    data_index, batch_inputs, batch_labels = generate_batch(
                        integer_tokens,
                        data_index,
                        batch_size,
                        num_skips,
                        skip_window
                    )

                    good_batch = is_batch_good(batch_inputs)

                feed_dict = {train_inputs: batch_inputs, train_labels: batch_labels}

                _, loss_val = session.run([optimizer, loss], feed_dict=feed_dict)
                average_loss += loss_val

                if step % 2000 == 0:
                    if step > 0:
                        average_loss /= 2000
                    print('Average loss at step ', step, ': ', average_loss)
                    average_loss = 0
                
            final_embeddings = normalized_embeddings.eval()
            saver.save(session, os.path.join(save_dir, 'embeddings_model'))

            return final_embeddings

def new_model(save_dir, integer_tokens, batch_size=128, 
              vocab_size=50000, embedding_size=128, 
              num_negative=64, num_steps=100001,
              num_skips=2, skip_window=1):
    """
    Create a new Word2Vec model with token
    vectors generated in the 'tokens' step.

    Parameters
    ----------
    save_dir : str
        Path to the output directory where model will be saved
    integer_tokens : str
        Path to the 1D token vectors
    """
    # Create TF graph
    with tf.device('/gpu:0'):
        graph =  tf.Graph()
        with graph.as_default():
            # If we are on the first run, initialize everything as normal
            train_inputs = tf.placeholder(tf.int32, shape=[batch_size], 
                                            name="train_inputs")
            train_labels = tf.placeholder(tf.int32, shape=[batch_size, 1], 
                                            name="train_labels")
            with tf.device('/cpu:0'):
                # Start embeddings w/ values uniformly distributed 
                # between -1 and 1
                embeddings = tf.Variable(tf.random_uniform([
                vocab_size,
                embedding_size
                ], -1.0, 1.0), name="embeddings")

                # Translates the train_inputs into the corresponding embedding
                embed = tf.nn.embedding_lookup(embeddings, train_inputs, 
                                                name="embedding_op")

                # Construct the variables for the noise contrastive estimation
                nce_weights = tf.Variable(tf.truncated_normal([
                    vocab_size,
                    embedding_size
                ], stddev=1.0 / math.sqrt(embedding_size)), name="nce_weights")

                nce_biases = tf.Variable(tf.zeros([vocab_size]), name="nce_biases")

                # Compute the average NCE loss for the batch.
                # tf.nce_loss automatically draws a new sample of the negative labels each
                # time we evaluate the loss.
                loss = tf.reduce_mean(tf.nn.nce_loss(
                    weights=nce_weights,
                    biases=nce_biases,
                    labels=train_labels,
                    inputs=embed,
                    num_sampled=num_negative,
                    num_classes=vocab_size
                ), name="loss")

                optimizer = tf.train.GradientDescentOptimizer(1.0).minimize(loss)

                norm = tf.sqrt(tf.reduce_sum(tf.square(embeddings), 1, 
                                keep_dims=True), name="norm")
                normalized_embeddings = embeddings / norm

                init = tf.global_variables_initializer()
                saver = tf.train.Saver()
            with tf.Session(graph=graph) as session:
                init.run()
                tf.add_to_collection('optimizer', optimizer)
                
                data_index = 0
                average_loss = 0

                for step in xrange(num_steps):
                    good_batch = False
                    while not good_batch:
                        data_index, batch_inputs, batch_labels = generate_batch(
                            integer_tokens,
                            data_index,
                            batch_size,
                            num_skips,
                            skip_window
                        )

                        good_batch = is_batch_good(batch_inputs)

                    feed_dict = {train_inputs: batch_inputs, train_labels: batch_labels}

                    _, loss_val = session.run([optimizer, loss], feed_dict=feed_dict)
                    average_loss += loss_val

                    if step % 2000 == 0:
                        if step > 0:
                            average_loss /= 2000
                        print('Average loss at step ', step, ': ', average_loss)
                        average_loss = 0

                final_embeddings = normalized_embeddings.eval()
                saver.save(session, os.path.join(save_dir, 'embeddings_model'))

                return final_embeddings