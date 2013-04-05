#!/usr/bin/env python

from distutils.core import setup

#-----------------------------------------------------------------------------
# Main setup
#-----------------------------------------------------------------------------

long_desc = \
"""
Keepass DB managing tool
-------------------------------------

This version can use Keepass v1 DB only.
This version can read DB only.
"""

setup(
    name = "kptool",
#    packages = ['kptool'],
    packages = find_packages(),
    version = "0.0.1",
    author = "WAKAYAMA Shirou",
    author_email = "shirou.faw@gmail.com",
    url = '',
    download_url = '',
    description = "Keepass v1 DB tool",
    long_description = long_desc, 
    license = "GPL v2",
    keywords = ["security", "password"],
    classifiers = [
        'Development Status :: 1 - Planning',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Topic :: Security',
        'Topic :: Utilities'
    ]
)
