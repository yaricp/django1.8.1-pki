# coding=utf-8

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.8/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '...your secret key of Django project...'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DJANGO_DEBUG', False)

ALLOWED_HOSTS = ['localhost', 'pki.yourhost.com']

ADMIN_MEDIA_PREFIX = '/admin/media/'

# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'project.pki',
    'account',
    'pinax_theme_bootstrap',
    'bootstrapform',
    #'project.center_auth_client', 
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'project.pki.middleware.PkiExceptionMiddleware',
    "account.middleware.LocaleMiddleware",
    "account.middleware.TimezoneMiddleware",
)

ROOT_URLCONF = 'project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'project','templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'account.context_processors.account',
                'pinax_theme_bootstrap.context_processors.theme',
            ],
        },
    },
]

WSGI_APPLICATION = 'project.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.8/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}



# Internationalization
# https://docs.djangoproject.com/en/1.8/topics/i18n/

DEFAULT_CHARSET = 'utf8'
LANGUAGES = (
        ('ru', 'RUS'),
        ('en', 'ENG'),
    )
LANGUAGE_CODE = 'ru-RU'

TIME_ZONE = 'Asia/Novosibirsk'

USE_I18N = True

USE_L10N = True

USE_TZ = True

LOGIN_REDIRECT_URL = '/'

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.8/howto/static-files/

STATIC_URL = '/static/'

STATIC_ROOT = os.path.join(BASE_DIR, 'files', 'static')
#STATICFILES_DIRS = (
#    os.path.join(BASE_DIR, 'static'),
#)

MEDIA_ROOT = os.path.join(BASE_DIR, 'files', 'media')
MEDIA_URL = '/media/'

AUTHENTICATION_BACKENDS = (
    #'django_auth_ldap.backend.LDAPBackend',
    'django.contrib.auth.backends.ModelBackend',
)

#AUTH_LDAP_SERVER_URI = "ldap://ldap.yourhost.com"
#
#import ldap
#from django_auth_ldap.config import LDAPSearch
#
#
#AUTH_LDAP_BIND_DN = "uid=proxyuser,ou=systemusers,dc=isp,dc=nsc,dc=ru"
#AUTH_LDAP_BIND_PASSWORD =  "proxy123"
#AUTH_LDAP_USER_SEARCH = LDAPSearch("ou=people,dc=isp,dc=nsc,dc=ru",
#    ldap.SCOPE_SUBTREE, "(uid=%(user)s)")
#
#AUTH_LDAP_USER_DN_TEMPLATE = "uid=%(user)s,ou=people,dc=isp,dc=nsc,dc=ru"
#
#AUTH_LDAP_USER_ATTR_MAP = {
#    "first_name": "givenName",
#    "last_name": "sn",
#    "email": "mail",
#    #"last_login":"",
#}

AUTH_PROFILE_MODULE = 'account.UserProfile'

#AUTH_LDAP_PROFILE_ATTR_MAP = {
#    "employee_number": "employeeNumber"
#}

#AUTH_LDAP_USER_FLAGS_BY_GROUP = {
#    "is_active": "cn=active,ou=django,ou=groups,dc=example,dc=com",
#    "is_staff": "cn=staff,ou=django,ou=groups,dc=example,dc=com",
#    "is_superuser": "cn=superuser,ou=django,ou=groups,dc=example,dc=com"
#}

#import logging

#logger = logging.getLogger('django_auth_ldap')
#logger.addHandler(logging.StreamHandler())
#logger.setLevel(logging.DEBUG)

## django-pki specific parameters

PKI_OPENSSL_BIN = '/usr/bin/openssl'
if DEBUG:
    print 'debugging mode'
    PKI_OPENSSL_CONF = os.path.join(BASE_DIR, 'ssl/openssl.cnf')
    PKI_LOG = os.path.join(BASE_DIR, 'log/django-pki.log')
    PKI_DIR = os.path.join(BASE_DIR, 'var/pki/ssl_store')
else:
    print 'main mode'
    PKI_OPENSSL_CONF = '/etc/ssl/openssl.cnf'
    PKI_LOG = '/var/log/django_pki/django-pki.log'
    PKI_DIR = '/var/pki/ssl_store'
PKI_LOGLEVEL = 'error'
JQUERY_URL = '/static/js/jquery.js'
PKI_SELF_SIGNED_SERIAL = 0x0
PKI_DEFAULT_KEY_LENGTH = 2048
PKI_DEFAULT_COUNTRY = 'RU'
PKI_DEFAULT_OU = 'LAN'
PKI_DEFAULT_STATE = 'Novosibirsk st.'
PKI_DEFAULT_LOCALITY = 'Novosibirsk'
PKI_DEFAULT_VALID_DAYS = 1825
PKI_DEFAULT_EMAIL = 'support@isp.nsc.ru'
PKI_PASSPHRASE_MIN_LENGTH = 7
PKI_ENABLE_GRAPHVIZ = True
PKI_GRAPHVIZ_DIRECTION = 'TD'
PKI_ENABLE_EMAIL = True
PKI_DEFAULT_ALGORITHM = 'sha512'

## django specific email configuration
EMAIL_HOST = "smtp.yourhost.com"
#EMAIL_HOST_USER = "relayuser"
#EMAIL_HOST_PASSWORD = "icanrelay"
DEFAULT_FROM_EMAIL = "pki@yourhost.com"

INSTALLED_APPS +=  (
        'debug_toolbar', 
        )
        
DEBUG_TOOLBAR_PANELS = [
        'debug_toolbar.panels.versions.VersionsPanel',
        'debug_toolbar.panels.timer.TimerPanel',
        'debug_toolbar.panels.settings.SettingsPanel',
        'debug_toolbar.panels.headers.HeadersPanel',
        'debug_toolbar.panels.request.RequestPanel',
        'debug_toolbar.panels.sql.SQLPanel',
        'debug_toolbar.panels.staticfiles.StaticFilesPanel',
        'debug_toolbar.panels.templates.TemplatesPanel',
        'debug_toolbar.panels.cache.CachePanel',
        'debug_toolbar.panels.signals.SignalsPanel',
        'debug_toolbar.panels.logging.LoggingPanel',
        'debug_toolbar.panels.redirects.RedirectsPanel',
    ]
    
INTERNAL_IPS = ['127.0.0.1', 'localhost']

if not DEBUG:
    RAVEN_CONFIG = {
        'dsn': 'http://blabla:blabla@sentry.yourhost.com/number_project',
    }

    # Добавьте raven в список установленных приложений
    INSTALLED_APPS +=  (
        'raven.contrib.django.raven_compat',
        )

#AUTH_CENTER_KEY = 'key for auth center'
#AUTH_CENTER_LENGHT_SESSION = 3600
#AUTH_CENTER_PASSWORD = 'password for nonexisten and new created users in django from LDAP'    # for non user
#AUTH_CENTER_DEFAULT_LOGIN_URL_REDIRECT = '/'
#AUTH_CENTER_LOGOUT_URL_REDIRECT = 'http://blabla.com'

