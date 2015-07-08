This project was forked from https://github.com/dkerwin/django-pki and adapted for version 1.8.1 of Django.
It is full worked project with system authentification and users accounts.

## Setup

1. git clone https://github.com/yaricp/django1.8.1-pki.git
2. cd django1.8.1-pki
3. virtualenv venv
4. source venv/bin/activate
5. pip install -r requirements.txt
6. python manage.py syncdb
7. python manage.py loaddata eku_and_ku.json

For debugging start with env variable DJANGO_DEBUG=true

env DJANGO_DEBUG=true python manage.py runserver

For main mode on work server start:

python manage.py runserver yourservername.com:80

or use UWSGI

## Settings

