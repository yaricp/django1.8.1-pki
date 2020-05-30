[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## About
It is Django application for manage of certificates in django admin.

In this center you can create certificate authorities for all your certificates.

Also you can create certificates for servers and for clients. 


## Dependencies

* pygraphviz


## Installation and run

from pypi:

    $ pip install django3-pki
    
from github:

    $ git clone https://github.com/yaricp/django1.8.1-pki/tree/django3.git


## Usage:

Insert 'pki' inside INSTALLED_APPS in your django project.

    $ python manage.py migrate pki
    $ python manage.py loaddata eku_and_ku
    
After than needs to create folder for center of certificates.
Go to https://<yourserver>:8000/admin/pki and push button "Refresh Metadata"
Bingo! Your PKI center ready!
You can manage your certificates in https://<yourserver>:8000/admin/pki

## Author
Yaroslav Pisarev
yaricp@gmail.com



