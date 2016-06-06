from setuptools import setup, find_packages

setup(
    name='burp',
    version='0.1',
    packages=find_packages(exclude=['test']),
    install_requires=['requests', 'mypy_lang'],
)
