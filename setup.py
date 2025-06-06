#!/usr/bin/env python

from setuptools import setup, find_packages
import coldfront

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='coldfront',
    version=coldfront.VERSION,
    description='HPC Resource Allocation System ',
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords='high-performance-computing resource-allocation',
    url='https://coldfront.readthedocs.io',
    project_urls={
        'Bug Tracker': 'https://github.com/ubccr/coldfront/issues',
        'Documentation': 'https://coldfront.readthedocs.io',
        'Source Code': 'https://github.com/ubccr/coldfront',
    },
    author='Andrew E. Bruno, Dori Sajdak, Mohammad Zia',
    license='GNU General Public License v3 (GPLv3)',
    python_requires='>=3.8',
    packages=find_packages(),
    install_requires=[
        'arrow==1.3.0',
        'asgiref==3.7.2',
        'bibtexparser==1.4.1',
        'blessed==1.20.0',
        'certifi==2024.2.2',
        'chardet==5.2.0',
        'charset-normalizer==3.3.2',
        'Django==4.2.11',
        'django-crispy-forms==2.1',
        'crispy-bootstrap4==2024.1',
        'django-environ==0.11.2',
        'django-filter==24.2',
        'django-model-utils==4.4.0',
        'django-picklefield==3.1',
        'django-q==1.3.9',
        'django-settings-export==1.2.1',
        'django-simple-history==3.5.0',
        'django-split-settings==1.3.0',
        'django-sslserver==0.22',
        'django-su==1.0.0',
        'djangorestframework==3.15.2',
        'doi2bib==0.4.0',
        'factory-boy==3.3.0',
        'Faker==24.1.0',
        'fontawesome-free==5.15.4',
        'FormEncode==2.1.0',
        'future==1.0.0',
        'humanize==4.9.0',
        'idna==3.6',
        'pyparsing==3.1.2',
        'python-dateutil==2.9.0.post0',
        'python-memcached==1.62',
        'pytz==2024.1',
        'redis==3.5.3',
        'requests==2.31.0',
        'six==1.16.0',
        'sqlparse==0.4.4',
        'text-unidecode==1.3',
        'types-python-dateutil==2.8.19.20240106',
        'typing_extensions==4.10.0',
        'urllib3==2.2.1',
        'wcwidth==0.2.13',
    ],
    entry_points={
        'console_scripts': [
            'coldfront = coldfront:manage',
        ],
    },
    include_package_data = True,
    classifiers=[
        'Programming Language :: Python :: 3',
        'Framework :: Django :: 3.2',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Systems Administration',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
    ]
)
