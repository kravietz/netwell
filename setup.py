#!/usr/bin/env python3

from setuptools import setup, find_packages

version = __import__('netwell').__version__

setup(
    name='netwell-ng',
    python_requires='>=3.6',
    version=version,
    author='Raymond Penners',
    author_email='raymond.penners@intenct.nl',
    description='Checker to determine if all is well',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type="text/markdown",
    url='https://github.com/kravietz/netwell-ng',
    keywords='network ping check test dns url availability',
    tests_require=[],
    license='MIT',
    install_requires=[
        'requests >= 2.0.0',
        'python-dateutil',
        'dnspython'],
    include_package_data=True,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Environment :: Web Environment',
        'Topic :: Internet',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    packages=find_packages(exclude=['example']),
    entry_points={
        'console_scripts': [
            'netwell = netwell.command:handle',
        ],
    },
)