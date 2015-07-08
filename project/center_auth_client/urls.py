# coding=utf-8
from django.conf.urls import *
from .views import *


urlpatterns = patterns('',
    url(r'^login$', login, 
            name="login"), 
    url(r'^logout$', 
            logout, 
            name="logout"),
    )
