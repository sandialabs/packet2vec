# Packet2Vec

## Installation and Setup

### Requirements

Packet2Vec requires Python 3.5 and the following 3rd-party libraries:

- six==1.12.0
- tensorflow==1.13.1
- joblib==0.13.2
- numpy==1.16.2
- h5py==2.9.0
- docopt==0.6.2
- matplotlib==3.0.3
- scikit_learn==0.21.3
- PyYAML==5.1.2

These third party requirements can be installed using the `requirements.txt` file:

```
pip install -r requirements.txt
```
To compile the required shared library (ParallelPcap), Packet2Vec requires the following software:

- CMake
- Boost >=1.66.0

To compile ParallelPcap:
```
cd ParallelPcap
mkdir build
cd build
cmake ..
make parallelpcap
```
The shared library must be placed in the same directory as `main.py`:
```
mv bin/parallelpcap.so ../..
```

---

## Complete Run

A complete Packet2Vec run uses a YAML file that specifies all the information required for generating features and training. The following YAML file is an example of one used for a complete run. Note that all text following `#` is a comment and is not necessary for the file to run. A sample configuration file is also provided in the repository.

```yaml
working: /path/to/working/directory          
train_data: /path/to/raw/training/data
test_data: /path/to/raw/testing/data
embeddings: /path/to/trained/embeddings/model
darpa: /path/to/groundtruth/csv/file
options:
  threads: 10
hyperparameters:
  ngram: 2
  vocab_size: 50000
classifiers:
  - rfc
  - gnb
```

```shell
python3 main.py run -c packet2vec_config.yml
```

## Directories
Packet2Vec requires the user to specify several directories and files:
- **working**: Working directory. Packet2Vec will use this directory to store temporary files. Currently, this directory also acts as the output directory.
- **train_data**: Directory containing raw pcap files for training.
- **test_data**: Directory containing raw pcap files for testing.
- **embeddings**: **Optional**. Path to a saved Word2Vec embeddings model. **If this option is present in the YAML file, Packet2Vec will update a saved Word2Vec model rather than training a new one**.
- **darpa**: Path to the groundtruth file for the DARPA2009 dataset.

## Available Configuration Options

Packet2Vec includes several optional user-definable parameters that can be specified in the YAML configuration file:

- **threads**: Number of processors to use to speed up ParallelPcap. Default is 1.

## Available ParallelPcap Hyperparameters

Packet2Vec includes several optional user-definable hyperparameters for the dictionary that can be specified in the YAML configuration file:

- **ngram**: The size of the ngrams ParallelPcap will compute.
- **vocab_size**: The size of the vocabulary for the ParallelPcap dictionary.

## Available Classifiers

Packet2Vec is configured to perform binary classification using two classifiers. Extending this code to add more classifiers should be relatively straightforward. 

- **rfc**: Random Forest Classifier.
- **gnb**: Naive Bayes Classifier.

## Other Modes
Packet2Vec allows the user to run any step in the process individually:

- **tokens**: The tokens mode will only generate a dictionary and integer representations of the raw pcap files.
```shell
python3 main.py tokens -c packet2vec_config.yml
```
- **embeddings**: The embeddings mode will only train the Word2Vec model. This requires the token vectors generated in the **tokens** step to be present in the working directory.
```shell
python3 main.py embeddings -c packet2vec_config.yml
```
- **features**: The features mode will use the trained Word2Vec model to generate embedding-based feature vectors. This mode requires that the integer representations and a saved embeddings model are present in the working directory.
```shell
python3 main.py features -c packet2vec_config.yml
```
- **classifiers**: The classifiers mode will train and test the binary classifiers on the generated feature vectors. This mode requires that the feature vectors generated in the **features** step are present in the working directory.
```shell
python3 main.py classifiers -c packet2vec_config.yml
```
