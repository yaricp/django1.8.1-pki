from django.urls import path

from .views import home_page, pki_chain, pki_download, pki_email, pki_refresh_metadata, pki_tree

app_name = "polls"
urlpatterns = [
    path("", home_page, name="home"),
    path(
        "download/(?P<model>certificate|certificateauthority)/<int:id>/(?P<ext>zip|crl|crt|p12)/",
        pki_download,
        name="download",
    ),
    path("chain/(?P<model>certificate|certificateauthority)/<int:id>/", pki_chain, name="chain"),
    path("tree/<int:id>/", pki_tree, name="tree"),
    path("email/(?P<model>certificate|certificateauthority)/(<int:id>/", pki_email, name="email"),
    path("refresh_metadata/", pki_refresh_metadata, name="refresh_metadata"),
]
