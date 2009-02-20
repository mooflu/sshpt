#!/usr/bin/env python

from distutils.core import setup

setup(name = 'sshpt',
      license = 'GPLv3',
      version = '1.0.3',
      description = 'SSH Power Tool - Run commands and copy files to multiple servers simultaneously WITHOUT pre-shared keys',
      author = 'Dan McDougall',
      author_email = 'YouKnowWho@YouKnowWhat.com',
      py_modules = ['sshpt'],
      scripts = ['sshpt'],
      packages = ['paramiko'],
      )
