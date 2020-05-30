import logging
import os

from django.contrib import admin, messages
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.urls import path

from .forms import CertificateAuthorityForm, CertificateForm, X509ExtensionForm
from .models import Certificate, CertificateAuthority, X509Extension
from .openssl import refresh_pki_metadata
from .settings import JQUERY_URL, PKI_DIR, PKI_LOG, PKI_LOGLEVEL
from .views import admin_delete, admin_history

if not os.path.exists(PKI_DIR):
    try:
        os.mkdir(PKI_DIR, int("0750"))
    except OSError as e:
        print("Failed to create PKI_DIR %s: %s" % (PKI_DIR, e))


LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}

logger = logging.getLogger("pki")

l_hdlr = logging.FileHandler(PKI_LOG)
l_hdlr.setFormatter(logging.Formatter("%(asctime)s %(levelname)s - %(module)s.%(funcName)s > %(message)s"))

if LOG_LEVELS[PKI_LOGLEVEL]:
    logger.setLevel(LOG_LEVELS[PKI_LOGLEVEL])

logger.addHandler(l_hdlr)


# Disable delete_selected
admin.site.disable_action("delete_selected")


class CertificateBaseAdmin(admin.ModelAdmin):
    """Base class for Certificate* Admin models"""

    save_on_top = True
    actions = []
    list_per_page = 25

    class Media:
        js = (
            JQUERY_URL,
            "js/jquery.tipsy.js",
            "js/pki_admin.min.js",
        )
        css = {
            "screen": ("css/pki.css", "css/tipsy.css",),
        }

    def save_model(self, request, obj, form, change):
        """Override builtin save_model function to pass user to model save"""
        obj.user = request.user
        obj.save()

    def refresh_metadata(self, request):
        """Rebuild PKI metadate. Renders openssl.conf template and cleans PKI_DIR."""

        ca_objects = list(CertificateAuthority.objects.all())
        refresh_pki_metadata(ca_objects)
        messages.info(request, "Successfully refreshed PKI metadata (%d certificate authorities)" % len(ca_objects))
        self.message_user(request, "Successfully refreshed PKI metadata (%d certificate authorities)" % len(ca_objects))
        return HttpResponseRedirect("../../")

    def get_urls(self):
        urls = super().get_urls()
        my_urls = [
            path("refresh_metadata/", self.admin_site.admin_view(self.refresh_metadata), name="refresh_metadata"),
        ]
        return my_urls + urls


class CertificateAuthorityAdmin(CertificateBaseAdmin):
    """CertificateAuthority admin definition"""

    form = CertificateAuthorityForm
    list_display = (
        "id",
        "common_name",
        "public",
        "serial_align_right",
        "valid_center",
        "chain_link",
        "tree_link",
        "parent_link",
        "expiry_date_show",
        "desc",
        "creation_date",
        "revocation_date",
        "child_certs",
        "download_link_zip",
        "download_link_crt",
        "download_link_crl",
        "email_link",
    )
    list_display_links = ("common_name",)
    list_filter = ("parent", "active", "extension", "public")
    radio_fields = {"action": admin.VERTICAL}
    search_fields = ["name", "common_name", "description"]
    date_hierarchy = "created"

    readonly_fields = (
        "expiry_date_show",
        "creation_date",
        "revocation_date",
        "serial",
        "chain",
        "certificate_dump",
        "ca_clock",
        "status",
    )
    fieldsets = (
        ("Define action", {"fields": ("action",),},),
        ("Documentation", {"fields": ("description",), "classes": ["wide",],},),
        ("Certificate Dump", {"fields": ("certificate_dump",), "classes": ["collapse", "wide",],},),
        (
            "Certificate",
            {
                "fields": (
                    "common_name",
                    "name",
                    "status",
                    "public",
                    "state",
                    "country",
                    "locality",
                    "organization",
                    "OU",
                    "email",
                    "key_length",
                    "valid_days",
                    "extension",
                    "passphrase",
                    "passphrase_verify",
                    "serial",
                    "expiry_date_show",
                    "creation_date",
                    "revocation_date",
                ),
                "classes": ["wide",],
            },
        ),
        ("Encoding options", {"fields": ("der_encoded",),},),
        (
            "Certificate signing",
            {
                "fields": ("ca_clock", "chain", "parent", "parent_passphrase", "crl_dpoints", "policy",),
                "classes": ["wide",],
            },
        ),
    )

    def delete_view(self, request, object_id, extra_context=None):
        return admin_delete(request, self.model._meta.model_name, object_id)

    def history_view(self, request, object_id, extra_context=None):
        return admin_history(request, self.model._meta.model_name, object_id)

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """Filter foreign key parent field.
        Skip CAs that dont have a matching x509 extension or are not active.
        """

        if db_field.name == "parent":
            kwargs["queryset"] = CertificateAuthority.objects.filter(
                extension__basic_constraints__contains="CA:TRUE", active=True
            ).exclude(extension__basic_constraints__contains="pathlen:0")
            return db_field.formfield(**kwargs)
        elif db_field.name == "extension":
            kwargs["queryset"] = X509Extension.objects.filter(
                basic_constraints__contains="CA:TRUE", key_usage__name__contains="keyCertSign"
            )
            print(kwargs["queryset"])
            print(db_field.formfield(**kwargs))
            return db_field.formfield(**kwargs)

        return super(CertificateAuthorityAdmin, self).formfield_for_foreignkey(db_field, request, **kwargs)


admin.site.register(CertificateAuthority, CertificateAuthorityAdmin)


class CertificateAdmin(CertificateBaseAdmin):
    """CertificateAuthority admin definition"""

    form = CertificateForm
    list_display = (
        "id",
        "common_name",
        "serial",
        "active",
        "chain_link",
        "parent",
        "expiry_date_show",
        "desc",
        "created",
        "revoked",
        "download_link_zip",
        "download_link_crt",
        "download_link_ovpn",
        "download_link_p12",
        "email_link",
    )
    list_display_links = ("common_name",)
    radio_fields = {"action": admin.VERTICAL}
    list_filter = ("parent", "active", "extension")
    search_fields = ["name", "description"]
    date_hierarchy = "created"
    readonly_fields = (
        "expiry_date_show",
        "creation_date",
        "revocation_date",
        "serial",
        "chain",
        "certificate_dump",
        "ca_clock",
        "status",
    )

    fieldsets = (
        ("Define action", {"fields": ("action",)}),
        ("Documentation", {"fields": ("description",), "classes": ["wide",],},),
        ("Certificate Dump", {"fields": ("certificate_dump",), "classes": ["collapse", "wide",],},),
        (
            "Certificate",
            {
                "fields": (
                    "status",
                    "common_name",
                    "name",
                    "country",
                    "state",
                    "locality",
                    "organization",
                    "OU",
                    "email",
                    "key_length",
                    "valid_days",
                    "extension",
                    "passphrase",
                    "passphrase_verify",
                    "serial",
                    "expiry_date_show",
                    "creation_date",
                    "revocation_date",
                ),
                "classes": ["wide",],
            },
        ),
        ("Multi-domain /  ectAltName", {"fields": ("subjaltname",), "classes": ["wide",],},),
        (
            "Encoding options",
            {
                "fields": ("der_encoded", "pkcs12_encoded", "pkcs12_passphrase", "pkcs12_passphrase_verify",),
                "classes": ["wide",],
            },
        ),
        (
            "Certificate signing",
            {"fields": ("ca_clock", "chain", "parent", "parent_passphrase", "crl_dpoints",), "classes": ["wide",],},
        ),
    )

    def save_model(self, request, obj, form, change):
        obj.user = request.user.username
        super(CertificateAdmin, self).save_model(request, obj, form, change)

    def delete_view(self, request, object_id, extra_context=None):
        return admin_delete(request, self.model._meta.model_name, object_id)

    def history_view(self, request, object_id, extra_context=None):

        return admin_history(request, self.model._meta.model_name, object_id)

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """Filter foreign key parent field.
        Skip CAs that dont have a matching x509 extension or are not active.
        Skip x509 extensions that are not sufficient for enduser certificates.
        """

        if db_field.name == "parent":
            print(kwargs)
            kwargs["queryset"] = CertificateAuthority.objects.filter(
                extension__basic_constraints__contains="CA:TRUE", active=True
            )
            # .filter(extension__basic_constraints__contains="pathlen:0")
            print(kwargs["queryset"])
            return db_field.formfield(**kwargs)

        elif db_field.name == "extension":
            kwargs["queryset"] = X509Extension.objects.filter(
                Q(basic_constraints__contains="CA:FALSE")
                | (
                    (Q(basic_constraints__contains="CA:TRUE") & Q(basic_constraints__contains="pathlen:0"))
                    & ~Q(key_usage__name__contains="keyCertSign")
                )
            )
            return db_field.formfield(**kwargs)

        return super(CertificateAdmin, self).formfield_for_foreignkey(db_field, request, **kwargs)


admin.site.register(Certificate, CertificateAdmin)


class X509ExtensionAdmin(CertificateBaseAdmin):
    """Admin instance for x509 extensions"""

    form = X509ExtensionForm
    list_display = (
        "id",
        "name",
        "description",
        "basic_constraints",
        "key_usage_csv",
        "ext_key_usage_csv",
        "created",
        "crld_point_center",
    )
    list_display_links = ("name",)
    search_fields = [
        "name",
        "description",
    ]
    date_hierarchy = "created"
    fieldsets = (
        (
            "X509 extension",
            {
                "fields": (
                    "name",
                    "description",
                    "basic_constraints",
                    "basic_constraints_critical",
                    "key_usage",
                    "key_usage_critical",
                    "extended_key_usage",
                    "extended_key_usage_critical",
                    "subject_key_identifier",
                    "authority_key_identifier",
                    "crl_distribution_point",
                ),
                "classes": ["wide",],
            },
        ),
    )

    def save_model(self, request, obj, form, change):
        if change:
            request.user.get_and_delete_messages()
        else:
            obj.user = request.user
            obj.save()

    def delete_view(self, request, object_id, extra_context=None):
        x509 = X509Extension.objects.get(pk=object_id)
        if x509.certificateauthority_set.all() or x509.certificate_set.all():
            logger.error('x509 extension "%s" cannot be removed because it is in use!' % x509.name)
            messages.error(request, 'x509 extension "%s" cannot be removed because it is in use!' % x509.name)
            return HttpResponseRedirect("../../")
        else:
            return super(X509ExtensionAdmin, self).delete_view(request, object_id, extra_context)

    def response_change(self, request, obj):
        messages.warning(request, "You cannot modify x509 extensions!")
        return HttpResponseRedirect("../")


admin.site.register(X509Extension, X509ExtensionAdmin)
