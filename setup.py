"""Setup configuration for ThreatForest"""
from setuptools import setup, find_packages

setup(
    name="threatforest",
    version="2.0.0",
    description="AI-Driven Threat Modeling & Attack Tree Generation",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "boto3>=1.34.0",
        "botocore>=1.34.0",
        "rich>=13.0.0",
        "click>=8.0.0",
        "pydantic>=2.0.0",
        "pyyaml>=6.0",
        "stix2>=3.0.0",
        "sentence-transformers>=2.2.0",
        "numpy>=1.21.0",
        "scikit-learn>=1.0.0",
        "aiofiles>=23.0.0",
    ],
    entry_points={
        "console_scripts": [
            "threatforest=threatforest_wizard:main",
        ],
    },
)
