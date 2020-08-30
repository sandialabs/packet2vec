"""
Packet2Vec. Automatic feature extraction and 
binary classification of raw network packet data.

Usage:
    main.py run          -c <config>
    main.py tokens       -c <config>
    main.py embeddings   -c <config>
    main.py features     -c <config>
    main.py classifier   -c <config>

Options:
    -h, --help                                  Show documentation
    -c <config>, --config <config>              Config file
"""
from docopt import docopt
import yaml
import os
import pcaps.process as pp
import pcaps.features as pf
import embeddings.train as te
import classifiers.train as train
import classifiers.test as test
from common import timer

def tokens(args):
    """
    Generate token vectors from raw pcap files. 

    Parameters
    ----------
    args : dict
        Configuration dict, typically loaded from YAML file
    """
    with timer("Generating Tokens and Dictionary"):
        pp.main(args['train_data'], args['working'], 
                num_threads=args['options']['threads'],
                ngram=[args['hyperparameters']['ngram']],
                vocab_size=args['hyperparameters']['vocab_size'])

def embeddings(args):
    """
    Train a Word2Vec model using Tensorflow with
    the token vectors generated in the 'tokens'
    step.

    Parameters
    ----------
    args : dict
        Configuration dict, typically loaded from YAML file
    """
    with timer("Training Word2Vec Model"):
        if 'embeddings' not in args.keys() or args['embeddings'] == None:
            te.create(args['working'], args['working'], 
                      args['hyperparameters']['vocab_size'])
        else:
            te.update(args['working'], args['embeddings'], args['working'], 
                      args['hyperparameters']['vocab_size'])
            

def features(args):
    """
    Applys the trained Word2Vec model to translate 
    the token vectors into feature vectors.

    Parameters
    ----------
    args : dict
        Configuration dict, typically loaded from YAML file
    """
    with timer("Generating Feature Vectors"):
        pf.finalize_feature_vectors(args['working'],
                                    args['working'],
                                    args['darpa'])

def classifiers(args):
    """
    Trains a binary classifier using the features
    generated in the 'features' step.

    Parameters
    ----------
    args : dict
        Configuration dict, typically loaded from YAML file
    """
    if 'classifiers' in args.keys():
        if 'rfc' in args['classifiers']:
            with timer("Training Random Forest"):
                train.randomForestClassifier(args['working'], args['working'])
            
            with timer("Testing Random Forest"):
                clf = os.path.join(args['working'], 'classifiers', 'rfc.joblib')
                test.test_classifier(args['working'], args['working'], 
                                     args['test_data'], clf, args['darpa'], 
                                     args['options']['threads'])


        if 'gnb' in args['classifiers']:
            with timer("Training Gaussian Naive Bayes"):
                train.naiveBayesClassifier(args['working'], args['working'])
            
            with timer("Testing Gaussian Naive Bayes"):
                clf = os.path.join(args['working'], 'classifiers', 'gnb.joblib')
                test.test_classifier(args['working'], args['working'], 
                                     args['test_data'], clf, args['darpa'], 
                                     args['options']['threads'])


def run(args):
    """
    Completes a full Packet2Vec run from raw
    pcap data to a trained classifier.

    Parameters
    ----------
    args : dict
        Configuration dict, typically loaded from YAML file
    """
    tokens(args)
    embeddings(args)
    features(args)
    classifiers(args)

if __name__ == '__main__':
    # Parse arguments and call appropriate method
    docargs = docopt(__doc__)

    # Program modes
    modes = {
        'run': run,
        'tokens': tokens,
        'embeddings': embeddings,
        'features': features,
        'classifiers': classifiers
    }

    f = modes[[mode for mode in modes if docargs[mode]][0]]
    c = docargs['--config']

    with open(c, 'r') as yml:
        args = yaml.safe_load(yml)
    
    with timer("Packet2Vec"):
        f(args)