from setuptools import setup, find_packages

VERSION = '0.2.5.0'

setup(
    name="lhub",
    version=VERSION,
    author="Chad Roberts",
    author_email="chad@logichub.com",
    description="LogicHub API Wrapper",
    long_description="A Python package for interacting with LogicHub APIs",
    packages=find_packages(),
    install_requires=[
        "requests",
        "multipledispatch",
    ],
    keywords=["python", "lhub", "LogicHub", "api", "security"],

    url="https://github.com/deathbywedgie/lhub",
    project_urls={
        "Bug Tracker": "https://github.com/deathbywedgie/lhub/issues",
    },
    # https://pypi.org/classifiers/
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Natural Language :: English",
    ]
)
