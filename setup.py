import os
import setuptools

from pki.version import version

this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setuptools.setup(
    name="django3-pki",  # Replace with your own username
    version=version,
    author="Yaric Pisarev",
    author_email="yaricp@gmail.com",
    description="Django application for manage\
                your own certificate center",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yaricp/django1.8.1-pki/tree/django3",
    include_package_data = True,
    packages=['pki'],
    package_dir={'pki':'pki'},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
