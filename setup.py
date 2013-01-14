#!/usr/bin/env python
from setuptools import setup, find_packages

dependencies = []

dependency_links = []

setup(
    name='django-http-auth',
    version='0.0.1',
    description='Simple django multisite Basic HTTP authentication middleware',
    author='TPG Bento Team',
    author_email='TPG-PBS-Bento@3pillarglobal.com',
    url='https://github.com/pbs/django-http-auth',
    packages=find_packages(),
    include_package_data=True,
    install_requires=dependencies,
    setup_requires = ['s3sourceuploader',]
)