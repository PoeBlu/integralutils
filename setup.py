#!/usr/bin/env python3

from setuptools import setup

setup(name='integralutils',
      version='1.0',
      description='Miscellaneous helper classes and utilities used in other Integral programs.',
      author='automationator',
      url='https://github.com/IntegralDefense/integralutils',
      packages=['integralutils'],
      with open('README.md') as r:
          long_description=r.read()
      include_package_data=True,
      #install_requires=[
      #      'beautifulsoup4',
      #      'python-dateutil',
      #      'requests'
      #],
      package_data = {
            'integralutils': ['etc/*']
      },
      scripts = [
            'bin/iu-findurls.py',
            'bin/iu-sandboxparser.py'
      ]
)
