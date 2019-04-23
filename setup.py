#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

setup(
    name='deux',
    version='1.2.0',
    description="Multifactor Authentication for Django Rest Framework",
    author="Robinhood Markets",
    author_email="opensource@robinhood.com",
    url="https://github.com/robinhood/deux",
    platforms=['any'],
    license='BSD',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        "djangorestframework>=2.4.3",
        "django-oauth-toolkit>=0.10.0",
        "django-otp>=0.3.5",
        "six>=1.10.0",
        "twilio>=5.4.0"
    ],
    tests_require=[
        "mock==2.0.0",
        "coverage>=3.0",
        "pytest-cov>=2.3.1,<3.0.0",
        "pytest-django>=3.0.0,<4.0.0",
        "pytest-runner>=2.9,<3.0",
    ],
)
