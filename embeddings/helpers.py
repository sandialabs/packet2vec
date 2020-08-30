import numpy as np
import collections
import operator
import random

def generate_batch(int_tokens, data_index, batch_size, num_skips, skip_window):
    """
    Generates a batch of data to create the word embeddings.

    Parameters
    ----------
    int_tokens : list
        A list of integer tokens
    data_index : int
        Index into the one big document
    batch_size : int
        How many words to consider
    num_skips : int
        TODO
    """
  
    assert batch_size % num_skips == 0
    assert num_skips <= 2 * skip_window

    lenOneDoc = len(int_tokens)

    batch = np.ndarray(shape=(batch_size), dtype=np.int32)
    labels = np.ndarray(shape=(batch_size, 1), dtype=np.int32)
    span = 2 * skip_window + 1 # [skip_window target skip_window]
    buffer = collections.deque(maxlen=span)

    if data_index + span > lenOneDoc:
        data_index = 0
    buffer.extend(int_tokens[data_index:(data_index + span)])
    data_index += span
    
    for i in range(batch_size // num_skips):
        target = skip_window # target label at center of the buffer
        targets_to_avoid = [skip_window]
        for j in range(num_skips):
            while target in targets_to_avoid:
                target = random.randint(0, span - 1)
            targets_to_avoid.append(target)
            batch[i * num_skips + j] = buffer[skip_window]
            labels[i * num_skips + j, 0] = buffer[target]

        if data_index == lenOneDoc:
            for word in int_tokens[0:span]:
                buffer.append(word)
            data_index = span
        else:
            buffer.append(int_tokens[data_index:(data_index + 1)][0])
            data_index += 1

    data_index = (data_index + lenOneDoc - span) % lenOneDoc
    return data_index, batch, labels

def is_batch_good(batch):
    """
    Checks if a batch of tokens is valid.

    Parameters
    ----------
    batch : list
        A list of integer tokens
    """
    my_dict = collections.defaultdict(int)
  
    for i in batch:
        my_dict[i] += 1
  
    sorted_x = sorted(my_dict.items(), key=operator.itemgetter(1), reverse=True)
    n = len(batch)

    if float(sorted_x[0][1]) / float(n) < 0.5:
        return True
    return False