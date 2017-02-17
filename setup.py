#!/usr/bin/env python3

from setuptools import setup

setup(name='integralutils',
      version='1.0',
      description='Miscellaneous helper classes and utilities used in other Integral programs.',
      author='automationator',
      url='https://github.com/IntegralDefense/integralutils',
      packages=['integralutils'],
      long_description=open('README.md').read(),
      include_package_data=True,
      install_requires=[
            'python-magic'
      ],
      package_data = {
            'integralutils': ['whitelists/*.ini']    
      }
)
