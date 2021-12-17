import itertools
import logging
import time
import typing


def time_function(f: typing.Callable):
    """Measure and log the execution time of the input function."""
    start = time.time()
    x = f()
    duration = time.time() - start
    duration = round(duration * 1000, 2)
    logging.info(f'[timing] executed {f.__name__} in {duration}ms')
    return x


def pairwise(iterable):
    """
    Return successive overlapping pairs taken from the input iterable.

    Taken from https://docs.python.org/3/library/itertools.html#itertools.pairwise
    """
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)
