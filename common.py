import time
from contextlib import ContextDecorator

class timer(ContextDecorator):
    def __init__(self, label):
        self.label = label
        self.start = None
    
    def __enter__(self):
        self.start = time.time()
        print('-------------------------------------------------')
        print('Starting: {}.'.format(self.label))
        print('-------------------------------------------------')
        return self
    
    def __exit__(self, *args):
        end = time.time()
        dt = end - self.start
        print('-------------------------------------------------')
        print('{} took {:.3f} seconds.'.format(self.label, dt))
        print('-------------------------------------------------')

def atoi(text):
    return int(text) if text.isdigit() else text
  
def natural_keys(text):
    return [ atoi(c) for c in re.split('(\d+)', text) ]