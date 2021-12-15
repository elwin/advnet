import itertools
import logging
import time
import typing


def time_function(f: typing.Callable):
    start = time.time()
    x = f()
    duration = time.time() - start
    duration = round(duration * 1000, 2)
    logging.info(f'[timing] executed {f.__name__} in {duration}ms')
    return x


def pairwise(iterable):
    # pairwise('ABCDEFG') --> AB BC CD DE EF FG
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)