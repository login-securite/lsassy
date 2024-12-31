# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import pathlib

from setuptools import find_packages, setup

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

setup(
    name="lsassy",
    version="3.1.13",
    author="Pixis",
    author_email="hackndo@gmail.com",
    description="Python library to extract credentials from lsass remotely",
    long_description=README,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["assets", "tests*"]),
    include_package_data=True,
    url="https://github.com/Hackndo/lsassy/",
    zip_safe=True,
    license="MIT",
    install_requires=["impacket", "netaddr", "pypykatz>=0.6.3", "rich"],
    python_requires=">=3.6",
    classifiers=(
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
    entry_points={
        "console_scripts": [
            "lsassy = lsassy.console:main",
        ],
    },
    test_suite="tests.test_lsassy",
)
