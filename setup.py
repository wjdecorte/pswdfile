from setuptools import setup, find_packages

version = "3.0.0"

setup(
    name='pswdfile',
    version=version,
    packages=find_packages(),
    url='http://scm.devcentral.equifax.com/svn/GISBI/trunk/app/python/dist/pswdfile-{0}.tar.gz'.format(version),
    license='GNU General Public License (GPL)',
    author='jwd3',
    author_email='jdecorte@decorteindustries.com',
    description='Password File - for storing passwords in encrypted format on the local file system',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: Unix',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2 :: Only'
    ],
    install_requires=[
        'click==6.7',
        'pycrypto==2.6.1'
    ],
    include_package_data=True,
    entry_points = {
        'console_scripts': [
            'pwutil = pswdfile.pwutil:main'
        ]
    },
    scripts=[
    ]
)
