#!/usr/bin/env python
import setuptools

dependencies = ["Django>=2.0,<=5.2"]


setuptools.setup(
    name='django-http-auth',
    version='2.2.1',
    description='Simple django multisite Basic HTTP authentication middleware',
    author='TPG Bento Team',
    author_email='TPG-PBS-Bento@3pillarglobal.com',
    url='https://github.com/pbs/django-http-auth',
    packages=setuptools.find_packages(),
    include_package_data=True,
    install_requires=dependencies,
    python_requires='>=3.10',
)
