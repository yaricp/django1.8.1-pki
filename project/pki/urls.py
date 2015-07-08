from django.conf.urls import *
from .views import *

urlpatterns = patterns('',
    url(r'^$', home_page, 
            name="home"), 
    url(r'^download/(?P<model>certificate|certificateauthority)/(?P<id>\d+)/(?P<ext>zip|crl|crt|p12)/$', 
            pki_download, 
            name="download"),
    url(r'^chain/(?P<model>certificate|certificateauthority)/(?P<id>\d+)/$', 
            pki_chain, 
            name="chain"),
    url(r'^tree/(?P<id>\d+)/$', 
            pki_tree, 
            name="tree"),
    url(r'^email/(?P<model>certificate|certificateauthority)/(?P<id>\d+)/$', 
            pki_email, 
            name="email"),
    url(r'^refresh_metadata/$', 
            pki_refresh_metadata, 
            name="refresh_metadata"),
)
