#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


version = '0.1.1'

setup(name='django-defender',
      version=version,
      description="redis based Django app that locks out users after too "
      "many failed login attempts.",
      long_description="redis based Django app based on speed, that locks out"
      "users after too many failed login attempts.",
      classifiers=[
          'Development Status :: 4 - Beta',
          'Framework :: Django',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: Apache Software License',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: Implementation :: PyPy',
          'Programming Language :: Python :: Implementation :: CPython',
          'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
          'Topic :: Security',
          'Topic :: Software Development :: Libraries',
          'Topic :: Software Development :: Libraries :: Python Modules', ],
      keywords='django, cache, security, authentication, throttle, login',
      author='Ken Cochrane',
      url='https://github.com/kencochrane/django-defender',
      author_email='kencochrane@gmail.com',
      license='Apache 2',
      packages=['defender'],
      install_requires=['Django>=1.6,<1.8', 'redis==2.10.3', 'hiredis==0.1.4'],
      tests_require=['mock', 'mockredispy', 'coverage', 'celery'],
      )
