import setuptools
from os import path
this_directory = path.abspath(path.dirname(__file__))

with open(path.join(this_directory, 'README.rst')) as fh:

    long_description = fh.read()

setuptools.setup(
    name='raok',
    version='0.5.4post1',
    scripts=[ 'raok-init.sh', 'raok.py', 'rasta.py'],
    author="Ales Stibal",
    author_email="astib@mag0.net",
    description="verbose TESTING radius authentication and accounting server and client",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/astibal/raok",
    packages=setuptools.find_packages(),

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)",
        "Operating System :: OS Independent",
    ],
    include_package_data=True,
    install_requires=[ "pyrad", "py3mschap"]
)
