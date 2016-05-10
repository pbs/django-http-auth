#!/usr/bin/env python
from setuptools import setup, find_packages

dependencies = ["Django>=1.4"]

dependency_links = []

setup(
    name='django-http-auth',
    version='1.1.0',
    description='Simple django multisite Basic HTTP authentication middleware',
    author='TPG Bento Team',
    author_email='TPG-PBS-Bento@3pillarglobal.com',
    url='https://github.com/pbs/django-http-auth',
    packages=find_packages(),
    include_package_data=True,
    install_requires=dependencies,
)
