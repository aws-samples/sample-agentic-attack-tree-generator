#!/usr/bin/env python3
"""
Setup script for ThreatForest.

This script provides an alternative to pyproject.toml for environments
that require setup.py for installation.
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    requirements = []
    if os.path.exists("requirements.txt"):
        with open("requirements.txt", "r", encoding="utf-8") as fh:
            requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    return requirements

setup(
    name="threatforest",
    version="1.0.0",
    author="ThreatForest Team",
    author_email="team@threatforest.dev",
    description="Agentic AI application for automated attack tree generation",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/threatforest/threatforest",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
    install_requires=[
        "boto3>=1.34.0",
        "botocore>=1.34.0",
        "click>=8.0.0",
        "rich>=13.0.0",
        "pydantic>=2.0.0",
        "pyyaml>=6.0.0",
        "requests>=2.28.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "bandit>=1.7.0",
        ],
        "test": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "tf=threatforest.cli:main",
            "threatforest=threatforest.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)