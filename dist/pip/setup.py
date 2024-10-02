from setuptools import setup
import os

def popen(x):
    res = os.popen(x).read()
    return res.strip() # decode("utf-8").strip()

with open("README.md") as fd:
    readme = fd.read()
r2_version = popen("../../configure -qV")

setup(
    name='radare2',
    version=r2_version,
    description="The UNIX friendly reverse engineering framework and toolchain",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="pancake",
    author_email="pancake@nopcode.org",
    url="https://www.radare.org/",
    packages=[
        'radare2',
    ],
    install_requires=[
        'r2pipe',
        'r2env'
    ],
    entry_points = {
        'console_scripts': [
            'r2 = radare2.main:main'
        ]
    },
)
