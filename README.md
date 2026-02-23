#django-http-auth
## Target
django-http-auth is a small app that allows the user of django with multisite support to lock access to specific sites using HTTP Basic Auth. It is intended to be used for preventing access to different environments and for sites under development.

## Installation
Install from cheeshop using pip:
>pip install django-http-auth

## Steps to upload the package to Nexus: 
1. If first time, create virtual env and install twine:
>python3 -m venv env
>source env/bin/activate
>pip install setuptools wheel Django twine  

2. Create a source distribution:
>python3 setup.py sdist bdist_wheel

3. Upload the package to Nexus:
>python3 -m twine upload --repository nexuspbs-internal dist/*

# Acknowledgements
Code inspired by:
* https://github.com/amrox/django-moat
