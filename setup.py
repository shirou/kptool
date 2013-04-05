from setuptools import setup, find_packages
import sys, os


sys.path.append('./tests')


#-----------------------------------------------------------------------------
# Main setup
#-----------------------------------------------------------------------------

version = '0.1'

deps = ['pycrypto']

if sys.version_info < (2,7):
    deps.append('argparse')

setup(name='kptool',
      version=version,
      description = "Keepass v1 DB tool",
      long_description = open('README.txt').read(),
      classifiers = [
        'Development Status :: 1 - Planning',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: End Users/Desktop',
	'License :: OSI Approved :: GNU General Public License (GPL)',
        'Topic :: Security',
        'Topic :: Utilities'
      ],
      keywords = ['security', 'password'],
      author = "WAKAYAMA Shirou",
      author_email = "shirou.faw@gmail.com",
      url='',
      license = "GPL v2",
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=deps,
      entry_points="""
      # -*- Entry points: -*-
      """,
      test_suite = 'tests.test'
      )
