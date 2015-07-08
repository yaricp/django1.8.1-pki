from django.conf.urls import patterns, include, url
from django.conf import settings
from django.contrib import admin
#from django.views.generic import TemplateView

from center_auth_client.views import login, logout

admin.autodiscover()

#handler500 = 'project.pki.views.show_exception'

urlpatterns = patterns('',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^accounts/', include('account.urls')),
    url(r'^logout_from_ecard/$', logout, name="logout_from_ecard"), 
    url(r'^', include('project.pki.urls')),
   
)

if settings.DEBUG:
    import debug_toolbar
    urlpatterns += patterns('',
        url(r'^__debug__/', include(debug_toolbar.urls)),
    )
