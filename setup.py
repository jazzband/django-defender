#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


version = '0.1'

setup(name='django-defender',
      version=version,
      description="redis based Django app that locks out users after too "
      "many failed login attempts.",
      long_description=open('README.md').read(),
      classifiers=[
          'Development Status :: 4 - Beta',
          'Framework :: Django',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: Apache 2 License',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
          'Topic :: Security',
          'Topic :: Software Development :: Libraries',
          'Topic :: Software Development :: Libraries :: Python Modules', ],
      keywords='django, cache, security, authentication',
      author='Ken Cochrane',
      url='https://github.com/kencochrane/django-defender',
      author_email='kencochrane@gmail.com',
      license='Apache 2',
      packages=['defender'],
      install_requires=['django==1.6.7', 'redis==2.10.3', 'hiredis==0.1.4', ],

      )
