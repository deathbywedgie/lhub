import functools

from lhub.exceptions.validation import VersionMinimumNotMet


def minimum_version(min: float, feature_label: str):
    def min_version_decorator(func):
        functools.wraps(func)

        def minimum_version_wrapper(*args, **kwargs):
            version = float(args[0].version.lstrip("m"))
            if min > version:
                raise VersionMinimumNotMet(
                    min_version=f"m{min}",
                    feature_label=feature_label
                )
            return func(*args, **kwargs)

        return minimum_version_wrapper
    return min_version_decorator
