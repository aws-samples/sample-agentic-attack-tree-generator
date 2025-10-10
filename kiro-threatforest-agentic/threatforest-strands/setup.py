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
        "boto3>=1.26.0",
        "rich>=13.0.0",
        "pydantic>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "threatforest=threatforest_wizard:main",
        ],
    },
)
