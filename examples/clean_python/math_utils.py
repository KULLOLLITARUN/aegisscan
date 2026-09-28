"""
Mathematical utilities module providing safe arithmetic and statistical functions.
"""

import math
from typing import List, Union

Number = Union[int, float]


def calculate_mean(values: List[Number]) -> float:
    """Calculate the arithmetic mean of a list of numbers."""
    if not values:
        raise ValueError("Cannot calculate mean of empty list")
    return sum(values) / len(values)


def calculate_std_dev(values: List[Number]) -> float:
    """Calculate the sample standard deviation of a list of numbers."""
    if len(values) < 2:
        return 0.0
    mean = calculate_mean(values)
    variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)


def is_prime(n: int) -> bool:
    """Determine whether a given integer is a prime number."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True
