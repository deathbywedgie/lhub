from setuptools import setup, find_packages

VERSION = '0.0.4'

setup(
    name="lhub",
    version=VERSION,
    author="Chad Roberts",
    author_email="chad@logichub.com",
    description="LogicHub API Wrapper",
    url="https://github.com/deathbywedgie/lhub",
    long_description="A Python package for interacting with LogicHub APIs",
    packages=find_packages(),
    install_requires=[
        "requests"
    ],
    keywords=["python", "lhub", "LogicHub"],

    # https://pypi.org/classifiers/
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Natural Language :: English",
    ]
)
