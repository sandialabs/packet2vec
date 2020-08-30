import parallelpcap
from common import timer

def main(pcap_path, output_dir, num_threads=1, ngram=[2], vocab_size=50000):
    """
    Uses the ParallelPcap library to generate the pcap binaries, 
    dictionary archive, and token vector files. Two different 
    token vector files are generated. 1D vectors of integers 
    (intVector) and 2D vectors of integers (intVectorVector)
    indexed by packet.

    Parameters
    ----------
    pcap_path : str
        Path to directory containing raw pcap files
    output_dir : str
        Path to the output directory where the generated
        files are stored
    num_threads : int
        How many threads ParallelPcap should use when 
        generating the dictionary
    ngram : list
        Sizes of ngrams ParallelPcap should use during 
        the dictionary generation
    vocab_size : int
        Size of the dictionary vocabulary
    """

    parallelpcap.setParallelPcapThreads(num_threads)
    parallelpcap.ReadPcap(
        pcap_path,
        ngram,
        vocab_size,
        output_dir,
        False
    )
