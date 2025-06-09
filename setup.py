from setuptools import setup, find_packages

setup(
    name="ip_lookup_tool",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "requests",
        "python-dotenv"
    ],
    entry_points={
        "console_scripts": [
            "iplookup=ip_lookup_enhanced:main"
        ],
    },
)
# This setup script defines the package metadata and dependencies for the IP lookup tool.
# It uses setuptools to find packages and specify the required libraries.