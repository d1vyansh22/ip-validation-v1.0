from setuptools import setup, find_packages

setup(
    name='ip-lookup-tool',
    version='1.1.0',
    description='A CLI tool for IP address lookup with Redis caching, batch mode, and monitoring.',
    author='IP Lookup Tool',
    packages=find_packages(),
    install_requires=[
        'requests',
        'redis',
        'python-dotenv',
    ],
    entry_points={
        'console_scripts': [
            'ip-lookup=ip_lookup_enhanced:main',
        ],
    },
    python_requires='>=3.7',
)
# This setup script defines the package metadata and dependencies for the IP lookup tool.
# It uses setuptools to find packages and specify the required libraries.