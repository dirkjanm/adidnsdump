from setuptools import setup

setup(name='adidnsdump',
      version='1.0.0',
      description='Active Directory Integrated DNS dumping by any authenticated user',
      license='MIT',
      classifiers=[
          'Intended Audience :: Information Technology',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
      ],
      author='Dirk-jan Mollema (@_dirkjan)',
      author_email='dirkjan.mollema@fox-it.com',
      url='https://github.com/dirkjanm/adidnsdump',
      packages=['adidnsdump'],
      install_requires=['impacket', 'ldap3==2.5.1'],
      entry_points={
          'console_scripts': ['adidnsdump=adidnsdump:main']
      }
     )
