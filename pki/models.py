import datetime
import re
from hashlib import md5 as md5_constructor
from logging import getLogger

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator, MinValueValidator, RegexValidator, URLValidator
from django.db import models
from django.urls import reverse
from django.utils.html import format_html

from .helper import get_pki_icon_html
from .openssl import Openssl, refresh_pki_metadata
from .settings import (
    PKI_DEFAULT_COUNTRY,
    PKI_DEFAULT_EMAIL,
    PKI_DEFAULT_KEY_LENGTH,
    PKI_DEFAULT_LOCALITY,
    PKI_DEFAULT_OU,
    PKI_DEFAULT_STATE,
    PKI_DEFAULT_VALID_DAYS,
    PKI_ENABLE_EMAIL,
    PKI_ENABLE_GRAPHVIZ,
    PKI_PASSPHRASE_MIN_LENGTH,
    STATIC_URL,
)

logger = getLogger("pki")


KEY_LENGTH = (
    (1024, "1024"),
    (2048, "2048"),
    (4096, "4096"),
)
POLICY = (
    ("policy_match", "policy_match"),
    ("policy_anything", "policy_anything"),
)
ACTIONS = (
    ("create", "Create certificate"),
    ("update", "Update description and export options"),
    ("revoke", "Revoke certificate"),
    ("renew", "Renew CSR (CN and key are kept)"),
)
COUNTRY = (
    ("AD", "AD"),
    ("AE", "AE"),
    ("AF", "AF"),
    ("AG", "AG"),
    ("AI", "AI"),
    ("AL", "AL"),
    ("AM", "AM"),
    ("AN", "AN"),
    ("AO", "AO"),
    ("AQ", "AQ"),
    ("AR", "AR"),
    ("AS", "AS"),
    ("AT", "AT"),
    ("AU", "AU"),
    ("AW", "AW"),
    ("AZ", "AZ"),
    ("BA", "BA"),
    ("BB", "BB"),
    ("BD", "BD"),
    ("BE", "BE"),
    ("BF", "BF"),
    ("BG", "BG"),
    ("BH", "BH"),
    ("BI", "BI"),
    ("BJ", "BJ"),
    ("BM", "BM"),
    ("BN", "BN"),
    ("BO", "BO"),
    ("BR", "BR"),
    ("BS", "BS"),
    ("BT", "BT"),
    ("BU", "BU"),
    ("BV", "BV"),
    ("BW", "BW"),
    ("BY", "BY"),
    ("BZ", "BZ"),
    ("CA", "CA"),
    ("CC", "CC"),
    ("CF", "CF"),
    ("CG", "CG"),
    ("CH", "CH"),
    ("CI", "CI"),
    ("CK", "CK"),
    ("CL", "CL"),
    ("CM", "CM"),
    ("CN", "CN"),
    ("CO", "CO"),
    ("CR", "CR"),
    ("CS", "CS"),
    ("CU", "CU"),
    ("CV", "CV"),
    ("CX", "CX"),
    ("CY", "CY"),
    ("CZ", "CZ"),
    ("DD", "DD"),
    ("DE", "DE"),
    ("DJ", "DJ"),
    ("DK", "DK"),
    ("DM", "DM"),
    ("DO", "DO"),
    ("DZ", "DZ"),
    ("EC", "EC"),
    ("EE", "EE"),
    ("EG", "EG"),
    ("EH", "EH"),
    ("ER", "ER"),
    ("ES", "ES"),
    ("ET", "ET"),
    ("FI", "FI"),
    ("FJ", "FJ"),
    ("FK", "FK"),
    ("FM", "FM"),
    ("FO", "FO"),
    ("FR", "FR"),
    ("FX", "FX"),
    ("GA", "GA"),
    ("GB", "GB"),
    ("GD", "GD"),
    ("GE", "GE"),
    ("GF", "GF"),
    ("GH", "GH"),
    ("GI", "GI"),
    ("GL", "GL"),
    ("GM", "GM"),
    ("GN", "GN"),
    ("GP", "GP"),
    ("GQ", "GQ"),
    ("GR", "GR"),
    ("GS", "GS"),
    ("GT", "GT"),
    ("GU", "GU"),
    ("GW", "GW"),
    ("GY", "GY"),
    ("HK", "HK"),
    ("HM", "HM"),
    ("HN", "HN"),
    ("HR", "HR"),
    ("HT", "HT"),
    ("HU", "HU"),
    ("ID", "ID"),
    ("IE", "IE"),
    ("IL", "IL"),
    ("IN", "IN"),
    ("IO", "IO"),
    ("IQ", "IQ"),
    ("IR", "IR"),
    ("IS", "IS"),
    ("IT", "IT"),
    ("JM", "JM"),
    ("JO", "JO"),
    ("JP", "JP"),
    ("KE", "KE"),
    ("KG", "KG"),
    ("KH", "KH"),
    ("KI", "KI"),
    ("KM", "KM"),
    ("KN", "KN"),
    ("KP", "KP"),
    ("KR", "KR"),
    ("KW", "KW"),
    ("KY", "KY"),
    ("KZ", "KZ"),
    ("LA", "LA"),
    ("LB", "LB"),
    ("LC", "LC"),
    ("LI", "LI"),
    ("LK", "LK"),
    ("LR", "LR"),
    ("LS", "LS"),
    ("LT", "LT"),
    ("LU", "LU"),
    ("LV", "LV"),
    ("LY", "LY"),
    ("MA", "MA"),
    ("MC", "MC"),
    ("MD", "MD"),
    ("MG", "MG"),
    ("MH", "MH"),
    ("ML", "ML"),
    ("MM", "MM"),
    ("MN", "MN"),
    ("MO", "MO"),
    ("MP", "MP"),
    ("MQ", "MQ"),
    ("MR", "MR"),
    ("MS", "MS"),
    ("MT", "MT"),
    ("MU", "MU"),
    ("MV", "MV"),
    ("MW", "MW"),
    ("MX", "MX"),
    ("MY", "MY"),
    ("MZ", "MZ"),
    ("NA", "NA"),
    ("NC", "NC"),
    ("NE", "NE"),
    ("NF", "NF"),
    ("NG", "NG"),
    ("NI", "NI"),
    ("NL", "NL"),
    ("NO", "NO"),
    ("NP", "NP"),
    ("NR", "NR"),
    ("NT", "NT"),
    ("NU", "NU"),
    ("NZ", "NZ"),
    ("OM", "OM"),
    ("PA", "PA"),
    ("PE", "PE"),
    ("PF", "PF"),
    ("PG", "PG"),
    ("PH", "PH"),
    ("PK", "PK"),
    ("PL", "PL"),
    ("PM", "PM"),
    ("PN", "PN"),
    ("PR", "PR"),
    ("PT", "PT"),
    ("PW", "PW"),
    ("PY", "PY"),
    ("QA", "QA"),
    ("RE", "RE"),
    ("RO", "RO"),
    ("RU", "RU"),
    ("RW", "RW"),
    ("SA", "SA"),
    ("SB", "SB"),
    ("SC", "SC"),
    ("SD", "SD"),
    ("SE", "SE"),
    ("SG", "SG"),
    ("SH", "SH"),
    ("SI", "SI"),
    ("SJ", "SJ"),
    ("SK", "SK"),
    ("SL", "SL"),
    ("SM", "SM"),
    ("SN", "SN"),
    ("SO", "SO"),
    ("SR", "SR"),
    ("ST", "ST"),
    ("SU", "SU"),
    ("SV", "SV"),
    ("SY", "SY"),
    ("SZ", "SZ"),
    ("TC", "TC"),
    ("TD", "TD"),
    ("TF", "TF"),
    ("TG", "TG"),
    ("TH", "TH"),
    ("TJ", "TJ"),
    ("TK", "TK"),
    ("TM", "TM"),
    ("TN", "TN"),
    ("TO", "TO"),
    ("TP", "TP"),
    ("TR", "TR"),
    ("TT", "TT"),
    ("TV", "TV"),
    ("TW", "TW"),
    ("TZ", "TZ"),
    ("UA", "UA"),
    ("UG", "UG"),
    ("UM", "UM"),
    ("US", "US"),
    ("UY", "UY"),
    ("UZ", "UZ"),
    ("VA", "VA"),
    ("VC", "VC"),
    ("VE", "VE"),
    ("VG", "VG"),
    ("VI", "VI"),
    ("VN", "VN"),
    ("VU", "VU"),
    ("WF", "WF"),
    ("WS", "WS"),
    ("YD", "YD"),
    ("YE", "YE"),
    ("YT", "YT"),
    ("YU", "YU"),
    ("ZA", "ZA"),
    ("ZM", "ZM"),
    ("ZR", "ZR"),
    ("ZW", "ZW"),
    ("ZZ", "ZZ"),
    ("ZZ", "ZZ"),
)


def validate_subject_altname(value):
    allowed = {
        "email": "^copy|[\w\-\.]+\@[\w\-\.]+\.\w{2,4}$",
        "IP": "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
        "DNS": "^[a-zA-Z0-9\-\.\*]+$",
    }

    items = value.split(",")
    for i in items:
        print(i)
        if not re.match("^\s*(email|IP|DNS)\s*:\s*.+$", i):
            print("Here")
            raise ValidationError(u'Item "%s" doesn\'t match specification' % i)
        else:
            kv = i.split(":")
            key = kv[0].lstrip().rstrip()
            val = kv[1].lstrip().rstrip()

            if key in allowed:
                if not re.match(allowed[key], val):
                    raise ValidationError(u'Invalid subjAltName value "%s" for key "%s" supplied' % (val, key))
            else:
                raise ValidationError(
                    u'Invalid subjAltName key supplied: "%s" (supported are %s)' % (key, ", ".join(allowed.keys()))
                )


def validate_crl_dp(value):
    items = value.split(",")

    for i in items:
        m = re.match("^\s*(?P<uri_key>(URI))\s*:\s*(?P<uri_value>\S+)$", i)
        if not m or (not m.group("uri_key") or not m.group("uri_value")):
            raise ValidationError(u'Item "%s" doesn\'t match specification' % i)
        try:
            URLValidator(m.group("uri_value"))
        except ValidationError:
            raise ValidationError('Given URI "%s" doesn\'t match the specification' % m.group("uri_value"))


class CertificateBase(models.Model):
    """Base class for all type of certificates"""

    description = models.CharField(max_length=255)
    country = models.CharField(max_length=2, choices=COUNTRY, default="%s" % PKI_DEFAULT_COUNTRY.upper())
    state = models.CharField(max_length=32, default=PKI_DEFAULT_STATE)
    locality = models.CharField(max_length=32, default=PKI_DEFAULT_LOCALITY)
    organization = models.CharField(max_length=64, default=PKI_DEFAULT_OU)
    OU = models.CharField(max_length=64, blank=True, null=True, default=PKI_DEFAULT_OU)
    email = models.EmailField(blank=True, null=True, default=PKI_DEFAULT_EMAIL)
    valid_days = models.IntegerField(validators=[MinValueValidator(1)], default=PKI_DEFAULT_VALID_DAYS)
    key_length = models.IntegerField(choices=KEY_LENGTH, default=PKI_DEFAULT_KEY_LENGTH)
    expiry_date = models.DateField(blank=True, null=True)
    created = models.DateTimeField(blank=True, null=True)
    revoked = models.DateTimeField(blank=True, null=True)
    active = models.BooleanField(default=True, help_text="Turn off to revoke this certificate")
    serial = models.CharField(max_length=64, blank=True, null=True)
    ca_chain = models.CharField(max_length=200, blank=True, null=True)
    der_encoded = models.BooleanField(default=False, verbose_name="DER encoding")
    user = models.CharField(max_length=64, blank=True, null=True)
    action = models.CharField(
        max_length=32, choices=ACTIONS, default="create", help_text="Yellow fields can/have to be modified!"
    )
    extension = models.ForeignKey(
        to="X509Extension", blank=True, null=True, verbose_name="x509 Extension", on_delete=models.CASCADE
    )
    crl_dpoints = models.CharField(
        max_length=255,
        verbose_name="CRL Distribution Points",
        null=True,
        blank=True,
        validators=[validate_crl_dp],
        help_text="Comma seperated list of URI elements. Example: URI:http://ca.local/ca.crl,...",
    )
    public = models.BooleanField(default=False, help_text="Public certificate")

    extension.x509extension_filter = True

    class Meta:
        abstract = True

    def status(self):
        """Overwrite the Boolean field admin for admin's changelist"""

        if not self.pk:
            return ""

        if self.active is True:
            return get_pki_icon_html("icon-yes.gif", "Certificate is valid", css="")
        else:
            return get_pki_icon_html("icon-no.gif", "Certificate is revoked", css="")

    status.allow_tags = True
    status.short_description = "status"

    def valid_center(self):
        """Overwrite the Booleanfield admin for admin's changelist"""

        if self.active is True:
            return get_pki_icon_html("icon-yes.gif", "Certificate is valid", id="active_%d" % self.pk)
        else:
            return get_pki_icon_html("icon-no.gif", "Certificate is revoked", id="active_%d" % self.pk)

    valid_center.allow_tags = True
    valid_center.short_description = "Valid"
    valid_center.admin_order_field = "active"

    def serial_align_right(self):
        """Make serial in changelist right justified"""

        return format_html('<div class="serial_align_right">%s</div>' % self.serial)

    serial_align_right.allow_tags = True
    serial_align_right.short_description = "Serial"
    serial_align_right.admin_order_field = "serial"

    def desc(self):
        """Limit description for changelist.
        Limit description to 30 characters to make changelist stay on one line per item.
        At least in most cases.
        """

        if len(self.description) > 30:
            return "%s..." % self.description[:30]
        else:
            return "%s" % self.description

    desc.allow_tags = True
    desc.admin_order_field = "description"

    def creation_date(self):
        """Return creation date in custom format"""

        return self.created.strftime("%Y-%m-%d %H:%M:%S")

    creation_date.admin_order_field = "created"

    def revocation_date(self):
        """Return revocation date in custom format"""
        if self.revoked:
            out = self.revoked.strftime("%Y-%m-%d %H:%M:%S")
        else:
            out = ""
        return out

    revocation_date.admin_order_field = "revoked"

    def expiry_date_show(self):
        """Return expiry date with days left.
        Return color marked expiry date based on days left.
        < 0 : EXPIRED text and red font color
        < 30: Orange color
        > 30: Just date and days left
        """
        now = datetime.datetime.now().date()
        if self.expiry_date:
            diff = self.expiry_date - now
        else:
            diff = now - now

        if not self.active:
            return format_html('<span class="revoked">%s (%sd)</span>' % (self.expiry_date, diff.days))

        if diff.days < 30 and diff.days >= 0:
            # span_class = ""
            return format_html('<span class="almost_expired">%s (%sd)</span>' % (self.expiry_date, diff.days))
        elif diff.days < 0:
            return format_html('<span class="expired">%s (EXPIRED)</span>' % self.expiry_date)
        else:
            return format_html("%s (%sd)" % (self.expiry_date, diff.days))

    expiry_date_show.allow_tags = True
    expiry_date_show.admin_order_field = "expiry_date"

    def chain(self):
        """Display chain with working arrows"""

        return self.ca_chain

    chain.allow_tags = True
    chain.short_description = "CA Chain"

    def chain_link(self):
        """Display chain link.
        If PKI_ENABLE_GRAPHVIZ is True a colored chain link is displayed. Otherwise
        a b/w chain icon without link is displayed.
        """

        if PKI_ENABLE_GRAPHVIZ:
            return format_html(
                '<a href="%s" target="_blank">%s</a>'
                % (
                    reverse("pki:chain", kwargs={"model": self.__class__.__name__.lower(), "id": self.pk}),
                    get_pki_icon_html("chain.png", "Show object chain", id="chain_link_%d" % self.pk),
                )
            )
        else:
            return get_pki_icon_html("chain.png", "Enable setting PKI_ENABLE_GRAPHVIZ")

    chain_link.allow_tags = True
    chain_link.short_description = "Chain"

    def email_link(self):
        """Display email link based on status.
        If PKI_ENABLE_EMAIL or certificate isn't active a disabled (b/w) icon is displayed.
        If no email address is set in the certificate a icon with exclamation mark is displayed.
        Otherwise the normal icon is returned.
        """

        if not PKI_ENABLE_EMAIL:
            return get_pki_icon_html(
                "mail--arrow_bw.png", "Enable setting PKI_ENABLE_EMAIL", id="email_delivery_%d" % self.pk
            )
        elif not self.active:
            return get_pki_icon_html(
                "mail--arrow_bw.png", "Certificate is revoked. Disabled", id="email_delivery_%d" % self.pk
            )
        else:
            if self.email:
                return format_html(
                    '<a href="%s">%s</a>'
                    % (
                        reverse("pki:email", kwargs={"model": self.__class__.__name__.lower(), "id": self.pk}),
                        get_pki_icon_html(
                            "mail--arrow.png",
                            "Send to '<strong>%s</strong>'" % self.email,
                            id="email_delivery_%d" % self.pk,
                        ),
                    )
                )
            else:
                return get_pki_icon_html(
                    "mail--exclamation.png", "Certificate has no email set. Disabled", id="email_delivery_%d" % self.pk
                )

    email_link.allow_tags = True
    email_link.short_description = "Delivery"

    def download_link_zip(self):
        """Return a download icon.
        Based on object status => clickable icon or just a b/w image
        """

        if (self.active and self.__class__.__name__.lower() == "certificateauthority" and self.public) or (
            self.active and self.__class__.__name__.lower() == "certificate"
        ):
            return format_html(
                '<a href="%s">%s</a>'
                % (
                    reverse(
                        "pki:download", kwargs={"model": self.__class__.__name__.lower(), "id": self.pk, "ext": "zip"}
                    ),
                    get_pki_icon_html(
                        "drive-download.png", "Download certificate zip", id="download_link_%d" % self.pk
                    ),
                )
            )
        else:
            return get_pki_icon_html(
                "drive-download_bw.png", "Certificate is revoked. Disabled", id="download_link_%d" % self.pk
            )

    download_link_zip.allow_tags = True
    download_link_zip.short_description = "Download ZIP"

    def download_link_crt(self):
        """Return a download icon.
        Based on object status => clickable icon or just a b/w image
        """

        if (self.active and self.__class__.__name__.lower() == "certificateauthority" and self.public) or (
            self.active and self.__class__.__name__.lower() == "certificate"
        ):
            return format_html(
                '<a href="%s">%s</a>'
                % (
                    reverse(
                        "pki:download", kwargs={"model": self.__class__.__name__.lower(), "id": self.pk, "ext": "crt"}
                    ),
                    get_pki_icon_html(
                        "drive-download.png", "Download certificate .crt", id="download_link_%d" % self.pk
                    ),
                )
            )
        else:
            return get_pki_icon_html(
                "drive-download_bw.png", "Certificate is revoked. Disabled", id="download_link_%d" % self.pk
            )

    download_link_crt.allow_tags = True
    download_link_crt.short_description = "Download CRT"

    def download_link_p12(self):
        """Return a download icon.
        Based on object status => clickable icon or just a b/w image
        """

        if (self.active and self.__class__.__name__.lower() == "certificateauthority" and self.public) or (
            self.active and self.__class__.__name__.lower() == "certificate"
        ):
            return format_html(
                '<a href="%s">%s</a>'
                % (
                    reverse(
                        "pki:download", kwargs={"model": self.__class__.__name__.lower(), "id": self.pk, "ext": "p12"}
                    ),
                    get_pki_icon_html(
                        "drive-download.png", "Download certificate .pkcs12", id="download_link_%d" % self.pk
                    ),
                )
            )
        else:
            return get_pki_icon_html(
                "drive-download_bw.png", "Certificate is revoked. Disabled", id="download_link_%d" % self.pk
            )

    download_link_p12.allow_tags = True
    download_link_p12.short_description = "Download PKCS12"

    def download_link_crl(self):
        """Return a download icon.
        Based on object status => clickable icon or just a b/w image
        """

        if (self.active and self.__class__.__name__.lower() == "certificateauthority" and self.public) or (
            self.active and self.__class__.__name__.lower() == "certificate"
        ):
            return format_html(
                '<a href="%s">%s</a>'
                % (
                    reverse(
                        "pki:download", kwargs={"model": self.__class__.__name__.lower(), "id": self.pk, "ext": "crl"}
                    ),
                    get_pki_icon_html(
                        "drive-download.png", "Download certificate .crl", id="download_link_%d" % self.pk
                    ),
                )
            )
        else:
            return get_pki_icon_html(
                "drive-download_bw.png",
                "Certificate is revoked or disabled or not public",
                id="download_link_%d" % self.pk,
            )

    download_link_crl.allow_tags = True
    download_link_crl.short_description = "Download CRL"

    def parent_link(self):
        """Return parent name.
        Returns parent's name when parent != None or self-signed
        """

        if self.parent:
            return format_html(
                '<a href="%s">%s</a>'
                % (reverse("admin:pki_certificateauthority_change", args=(self.parent.pk,)), self.parent.common_name)
            )
        else:
            return format_html(
                '<a href="%s">self-signed</a>'
                % (reverse("admin:pki_%s_change" % self.__class__.__name__.lower(), args=(self.pk,)))
            )

    parent_link.allow_tags = True
    parent_link.short_description = "Parent"
    parent_link.admin_order_field = "parent"

    def certificate_dump(self):
        """Dump of the certificate"""

        if self.pk and self.active:
            a = Openssl(self)
            return format_html('<textarea id="certdump">%s</textarea>' % a.dump_certificate())
        else:
            return "Nothing to display"

    certificate_dump.allow_tags = True
    certificate_dump.short_description = "Certificate dump"

    def ca_clock(self):
        """ CA Clock"""
        return format_html(
            '<div id="clock_container"><img src="%s/img/clock-frame.png" style="margin-right:5px"/>'
            '<span id="clock"></span></div>' % STATIC_URL
        )

    ca_clock.allow_tags = True
    ca_clock.short_description = "CA clock"

    def update_changelog(self, obj, user, action, changes):
        """Update changelog for given object"""

        PkiChangelog(
            model_id=ContentType.objects.get_for_model(obj).pk,
            object_id=obj.pk,
            action=action,
            user=user,
            changes="; ".join(changes),
        ).save()

    def delete_changelog(self, obj):
        """Delete changelogs for a given object"""

        PkiChangelog.objects.filter(model_id=ContentType.objects.get_for_model(obj).pk, object_id=obj.pk).delete()


class CertificateAuthority(CertificateBase):
    """Certificate Authority model"""

    common_name = models.CharField(max_length=64, unique=True)
    name = models.CharField(
        max_length=64,
        unique=True,
        validators=[RegexValidator("[a-zA-Z0-9-_\.]+", message="Name may only contain characters in range a-Z0-9_-.")],
        help_text="Only change the suggestion if you really know what you're doing",
    )
    parent = models.ForeignKey("self", blank=True, null=True, on_delete=models.CASCADE)
    passphrase = models.CharField(
        max_length=255,
        blank=True,
        validators=[MinLengthValidator(PKI_PASSPHRASE_MIN_LENGTH)],
        help_text="At least 8 characters. Remeber this passphrase - <font color='red'> \
                    <strong>IT'S NOT RECOVERABLE</strong></font><br>Will be shown as md5 encrypted string",
    )
    parent_passphrase = models.CharField(
        max_length=255, null=True, blank=True, help_text="Leave empty if this is a top-level CA"
    )
    policy = models.CharField(
        max_length=50,
        choices=POLICY,
        default="policy_anything",
        help_text="policy_match: All subject settings must \
                    match the signing CA<br> \
                    policy_anything: Nothing has to match the \
                    signing CA",
    )

    class Meta:
        db_table = "pki_certificateauthority"
        verbose_name = "Certificate Authorities"
        verbose_name_plural = "Certificates Authorities"
        permissions = (("can_download", "Can download",),)

    def __unicode__(self):
        return self.common_name

    def __str__(self):
        return self.common_name

    def save(self, *args, **kwargs):
        """Save the CertificateAuthority object"""

        # Set user to None if it's missing
        c_user = getattr(self, "user", None)
        # Variables to track changes
        c_action = self.action
        c_list = []

        if self.pk:
            if self.action in ("update", "revoke", "renew"):
                action = Openssl(self)
                prev = CertificateAuthority.objects.get(pk=self.pk)

                if self.action in ("revoke", "renew"):
                    if self.action == "revoke":
                        if not self.parent:
                            raise Exception("You cannot revoke a self-signed certificate! No parent => No revoke")

                        action.revoke_certificate(self.parent_passphrase)
                        action.generate_crl(self.parent.name, self.parent_passphrase)

                        prev.active = False
                        prev.der_encoded = False
                        prev.revoked = datetime.datetime.now()

                        c_list.append('Revoked certificate "%s"' % self.common_name)
                    elif self.action == "renew":
                        c_list.append('Renewed certificate "%s"' % self.common_name)

                        if self.parent and not action.get_revoke_status_from_cert():
                            action.revoke_certificate(self.parent_passphrase)
                            action.generate_crl(self.parent.name, self.parent_passphrase)

                        self.rebuild_ca_metadata(modify=True, task="replace")

                        if not self.parent:
                            action.generate_self_signed_cert()
                            action.generate_crl(self.name, self.passphrase)
                        else:
                            action.generate_csr()
                            action.sign_csr()
                            action.generate_crl(self.parent.name, self.parent_passphrase)

                        action.update_ca_chain_file()

                        prev.created = datetime.datetime.now()
                        delta = datetime.timedelta(self.valid_days)
                        prev.expiry_date = datetime.datetime.now() + delta

                        if prev.valid_days != self.valid_days:
                            c_list.append("Changed valid days from %d to %d" % (prev.valid_days, self.valid_days))

                        prev.valid_days = self.valid_days
                        prev.active = True
                        prev.revoked = None

                        if prev.country != self.country:
                            c_list.append('Updated country to "%s"' % self.country)
                        if prev.locality != self.locality:
                            c_list.append('Updated locality to "%s"' % self.locality)
                        if prev.organization != self.organization:
                            c_list.append('Updated organization to "%s"' % self.organization)
                        if prev.email != self.email:
                            c_list.append('Updated email to "%s"' % self.email)
                        if prev.OU != self.OU:
                            c_list.append('Updated OU to "%s"' % self.OU)

                        prev.country = self.country
                        prev.locality = self.locality
                        prev.organization = self.organization
                        prev.email = self.email
                        prev.OU = self.OU

                        prev.serial = action.get_serial_from_cert()
                        c_list.append("Serial number changed to %s" % prev.serial)

                    garbage = []
                    id_dict = {
                        "cert": [],
                        "ca": [],
                    }

                    from .views import chain_recursion as r_chain_recursion

                    r_chain_recursion(self.id, garbage, id_dict)

                    for i in id_dict["cert"]:
                        x = Certificate.objects.get(pk=i)
                        x.active = False
                        x.der_encoded = False
                        x.pkcs12_encoded = False
                        x.revoked = datetime.datetime.now()

                        super(Certificate, x).save(*args, **kwargs)
                        self.Update_Changelog(
                            obj=x,
                            user=c_user,
                            action="broken",
                            changes=(['Broken by %s of CA "%s"' % (c_action, self.common_name),]),
                        )

                    for i in id_dict["ca"]:
                        x = CertificateAuthority.objects.get(pk=i)
                        x.active = False
                        x.der_encoded = False
                        x.revoked = datetime.datetime.now()
                        super(CertificateAuthority, x).save(*args, **kwargs)
                        if x.pk != self.pk:
                            self.Update_Changelog(
                                obj=x,
                                user=c_user,
                                action="broken",
                                changes=(['Broken by %s of CA "%s"' % (c_action, self.common_name),]),
                            )

                if prev.description != self.description:
                    c_list.append('Updated description to "%s"' % self.description)
                    prev.description = self.description

                if prev.public != self.public:
                    c_list.append('Updated public to "%s"' % self.public)
                    prev.public = self.public

                if prev.der_encoded is not self.der_encoded:
                    c_list.append("DER encoding set to %s" % self.der_encoded)

                if self.der_encoded and self.action != "revoke":
                    action.generate_der_encoded()
                else:
                    action.remove_der_encoded()

                self = prev
                self.action = "update"
            else:
                raise Exception("Invalid action %s supplied" % self.action)
        else:
            self.created = datetime.datetime.now()
            delta = datetime.timedelta(self.valid_days)
            self.expiry_date = datetime.datetime.now() + delta

            self.active = True

            self.action = "update"

            print("Start REBuild")
            self.rebuild_ca_metadata(modify=True, task="append")

            action = Openssl(self)
            action.generate_key()

            if not self.parent:
                action.generate_self_signed_cert()
            else:
                action.generate_csr()
                action.sign_csr()

            if self.der_encoded:
                action.generate_der_encoded()

            action.generate_crl(self.name, self.passphrase)

            self.serial = action.get_serial_from_cert()

            chain = []
            chain_str = ""

            p = self.parent

            if not self.parent:
                chain.append("self-signed")
            else:
                chain.append(self.common_name)
                while p:
                    chain.append(p.common_name)
                    p = p.parent

            chain.reverse()

            for i in chain:
                if chain_str == "":
                    chain_str += "%s" % i
                else:
                    chain_str += "&nbsp;&rarr;&nbsp;%s" % i

            self.ca_chain = chain_str
            action.update_ca_chain_file()

            self.passphrase = md5_constructor(self.passphrase.encode("utf-8")).hexdigest()

            c_list.append('Created certificate "%s"' % self.common_name)

        self.parent_passphrase = None

        super(CertificateAuthority, self).save(*args, **kwargs)

        self.update_changelog(obj=self, user=c_user, action=c_action, changes=c_list)

    def delete(self, passphrase, *args, **kwargs):
        """Delete the CertificateAuthority object"""

        logger.info("Certificate %s is going to be deleted" % self.name)

        self.remove_chain = []

        revoke_required = True

        def chain_recursion(r_id):

            ca = CertificateAuthority.objects.get(pk=r_id)
            self.remove_chain.append(ca.pk)

            child_cas = CertificateAuthority.objects.filter(parent=r_id)
            if child_cas:
                for ca in child_cas:
                    chain_recursion(ca.pk)

        if not self.parent:
            logger.info("No revoking of certitifcates. %s is a toplevel CA" % self.name)
            revoke_required = False

        chain_recursion(self.pk)
        logger.info("Full chain is %s and pf is %s" % (self.remove_chain, self.passphrase))

        if revoke_required:
            a = Openssl(CertificateAuthority.objects.get(pk=self.pk))
            a.revoke_certificate(passphrase)
            a.generate_crl(ca=self.parent.name, pf=passphrase)

        self.rebuild_ca_metadata(modify=True, task="exclude", skip_list=self.remove_chain)

        self.Delete_Changelog(obj=self)

        super(CertificateAuthority, self).delete(*args, **kwargs)

    def rebuild_ca_metadata(self, modify, task, skip_list=[]):
        """Wrapper around refresh_pki_metadata"""

        if modify:
            print("modify")
            if task == "append":
                print("append")
                known_cas = list(CertificateAuthority.objects.all())
                known_cas.append(self)
            elif task == "replace":
                print("replace")
                known_cas = list(CertificateAuthority.objects.exclude(pk=self.pk))
                known_cas.append(self)
            elif task == "exclude":
                print("exclude")
                known_cas = list(CertificateAuthority.objects.exclude(pk__in=skip_list))
        else:
            known_cas = list(CertificateAuthority.objects.all())

        refresh_pki_metadata(known_cas)

    def is_edge_ca(self):
        """Return true if the CA is a edge CA that cannot contain other CA's"""

        return "pathlen:0" in self.extension.basic_constraints.lower()

    def tree_link(self):

        if PKI_ENABLE_GRAPHVIZ:
            return format_html(
                '<a href="%s" target="_blank">%s</a>'
                % (
                    reverse("pki:tree", kwargs={"id": self.pk}),
                    get_pki_icon_html("tree.png", "Show CA tree", id="tree_link_%d" % self.pk),
                )
            )
        else:
            return get_pki_icon_html("tree_disabled.png", "Enable setting PKI_ENABLE_GRAPHVIZ")

    tree_link.allow_tags = True
    tree_link.short_description = "Tree"

    def child_certs(self):
        """Show associated client certificates"""

        if not self.is_edge_ca():
            return get_pki_icon_html("blue-document-tree_bw.png", "No children", id="show_child_certs_%d" % self.pk)
        else:
            return format_html(
                '<a href="%s" target="_blank">%s</a>'
                % (
                    "?".join([reverse("admin:pki_certificate_changelist"), "parent__id__exact=%d" % self.pk]),
                    get_pki_icon_html(
                        "blue-document-tree.png", "Show child certificates", id="show_child_certs_%d" % self.pk
                    ),
                )
            )

    child_certs.allow_tags = True
    child_certs.short_description = "Children"


class Certificate(CertificateBase):
    """Certificate model"""

    common_name = models.CharField(max_length=64)
    name = models.CharField(
        max_length=64,
        validators=[RegexValidator("[a-zA-Z0-9-_\.]+", message="Name may only contain characters in range a-Z0-9_-.")],
        help_text="Only change the suggestion if you really know what you're doing",
    )
    parent = models.ForeignKey(
        "CertificateAuthority",
        blank=True,
        null=True,
        on_delete=models.CASCADE,
        help_text="Leave blank to generate self-signed certificate",
    )
    passphrase = models.CharField(
        max_length=255, null=True, blank=True, validators=[MinLengthValidator(PKI_PASSPHRASE_MIN_LENGTH)]
    )
    parent_passphrase = models.CharField(max_length=255, blank=True, null=True)
    pkcs12_encoded = models.BooleanField(default=False, verbose_name="PKCS#12 encoding")
    pkcs12_passphrase = models.CharField(
        max_length=255, verbose_name="PKCS#12 passphrase", blank=True, null=True, validators=[MinLengthValidator(8)]
    )
    subjaltname = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name="SubjectAltName",
        validators=[validate_subject_altname],
        help_text="Comma seperated list of alt names. Valid are DNS:www.xyz.com, IP:1.2.3.4 and email:a@b.com in any \
                    combination. Refer to the official openssl documentation for details",
    )

    class Meta:
        db_table = "pki_certificate"
        verbose_name = "Certificate"
        verbose_name_plural = "Certificates"
        permissions = (("can_download", "Can download",),)
        unique_together = (
            ("name", "parent"),
            ("common_name", "parent"),
        )

    def __unicode__(self):
        return self.common_name

    def __str__(self):
        return self.common_name

    @property
    def is_server_side_cert(self):
        return self.extension.name == "v3_edge_cert_server"

    def download_link_ovpn(self):
        """Return a download icon.
        Based on object status => clickable icon or just a b/w image
        """

        if (
            self.active
            and self.extension.name.find("client") != -1
            and self.__class__.__name__.lower() == "certificate"
        ):
            return format_html(
                '<a href="%s">%s</a>'
                % (
                    reverse(
                        "pki:download", kwargs={"model": self.__class__.__name__.lower(), "id": self.pk, "ext": "ovpn"}
                    ),
                    get_pki_icon_html(
                        "drive-download.png", "Download certificate ovpn", id="download_link_%d" % self.pk
                    ),
                )
            )
        else:
            return get_pki_icon_html("drive-download_bw.png", "Disabled", id="download_link_%d" % self.pk)

    download_link_ovpn.allow_tags = True
    download_link_ovpn.short_description = "Download OVPN"

    def save(self, *args, **kwargs):
        """Save the Certificate object"""

        c_user = getattr(self, "user", None)
        c_action = self.action
        c_list = []

        if self.pk:
            if self.action in ("update", "revoke", "renew"):
                action = Openssl(self)
                prev = Certificate.objects.get(pk=self.pk)
                if self.action == "revoke":
                    if not self.parent:
                        raise Exception("You cannot revoke a self-signed certificate! No parent => No revoke")

                    # Revoke and generate CRL
                    action.revoke_certificate(self.parent_passphrase)
                    action.generate_crl(self.parent.name, self.parent_passphrase)

                    # Modify fields
                    prev.active = False
                    prev.der_encoded = False
                    prev.pkcs12_encoded = False
                    prev.revoked = datetime.datetime.now()
                    c_list.append('Revoked certificate "%s"' % self.common_name)
                elif self.action == "renew":
                    c_list.append('Renewed certificate "%s"' % self.common_name)

                    # Revoke if certificate is active
                    if self.parent and not action.get_revoke_status_from_cert():
                        action.revoke_certificate(self.parent_passphrase)
                        action.generate_crl(self.parent.name, self.parent_passphrase)

                    # Renew certificate and update CRL
                    if not self.parent:
                        action.generate_self_signed_cert()
                    else:
                        action.generate_csr()
                        action.sign_csr()
                        action.generate_crl(self.parent.name, self.parent_passphrase)

                    # Modify fields
                    prev.created = datetime.datetime.now()
                    delta = datetime.timedelta(self.valid_days)
                    prev.expiry_date = datetime.datetime.now() + delta

                    if prev.valid_days != self.valid_days:
                        c_list.append("Changed valid days from %d to %d" % (prev.valid_days, self.valid_days))

                    prev.valid_days = self.valid_days
                    prev.active = True
                    prev.revoked = None

                    # Make sure possibly updated fields are saved to DB
                    if prev.country != self.country:
                        c_list.append('Updated country to "%s"' % self.country)
                    if prev.locality != self.locality:
                        c_list.append('Updated locality to "%s"' % self.locality)
                    if prev.organization != self.organization:
                        c_list.append('Updated organization to "%s"' % self.organization)
                    if prev.email != self.email:
                        c_list.append('Updated email to "%s"' % self.email)
                    if prev.OU != self.OU:
                        c_list.append('Updated OU to "%s"' % self.OU)

                    prev.country = self.country
                    prev.locality = self.locality
                    prev.organization = self.organization
                    prev.email = self.email
                    prev.OU = self.OU

                    # Get the new serial
                    prev.serial = action.get_serial_from_cert()
                    c_list.append("Serial number changed to %s" % prev.serial)

                if self.action != "revoke":
                    if prev.pkcs12_encoded != self.pkcs12_encoded:
                        c_list.append("PKCS12 encoding set to %s" % self.der_encoded)

                    if self.pkcs12_encoded:
                        if prev.pkcs12_encoded and prev.pkcs12_passphrase == self.pkcs12_passphrase:
                            logger.debug("PKCS12 passphrase is unchanged. Nothing to do")
                        else:
                            action.generate_pkcs12_encoded()
                    else:
                        action.remove_pkcs12_encoded()
                        self.pkcs12_passphrase = prev.pkcs12_passphrase = None

                    if self.pkcs12_passphrase:
                        prev.pkcs12_passphrase = md5_constructor(self.pkcs12_passphrase).hexdigest()
                    else:
                        prev.pkcs12_passphrase = None

                    if prev.der_encoded is not self.der_encoded:
                        c_list.append("DER encoding set to %s" % self.der_encoded)

                    if self.der_encoded:
                        action.generate_der_encoded()
                    else:
                        action.remove_der_encoded()

                # Update description. This is always allowed
                if prev.description != self.description:
                    c_list.append('Updated description to "%s"' % self.description)
                    prev.description = self.description

                # Save the data
                self = prev
                self.action = "update"
            else:
                raise Exception("Invalid action %s supplied" % self.action)
        else:
            self.created = datetime.datetime.now()
            delta = datetime.timedelta(self.valid_days)
            self.expiry_date = datetime.datetime.now() + delta

            self.active = True

            logger.info("***** { New certificate generation: %s } *****" % self.name)

            action = Openssl(self)
            action.generate_key()

            if self.parent:
                action.generate_csr()
                action.sign_csr()
                self.ca_chain = self.parent.ca_chain
                if self.ca_chain == "self-signed":
                    self.ca_chain = self.parent.name
            else:
                action.generate_self_signed_cert()
                self.ca_chain = "self-signed"

            self.serial = action.get_serial_from_cert()

            if self.der_encoded:
                action.generate_der_encoded()

            if self.pkcs12_encoded:
                action.generate_pkcs12_encoded()

            if self.passphrase:
                self.passphrase = md5_constructor(self.passphrase).hexdigest()

            c_list.append('Created certificate "%s"' % action.subj)

        self.parent_passphrase = None
        super(Certificate, self).save(*args, **kwargs)

        self.update_changelog(obj=self, user=c_user, action=c_action, changes=c_list)

    def delete(self, passphrase, *args, **kwargs):
        """Delete the Certificate object"""

        a = Openssl(self)

        if self.parent:
            a.revoke_certificate(passphrase)
            a.generate_crl(ca=self.parent.name, pf=passphrase)

        a.remove_complete_certificate()

        self.Delete_Changelog(obj=self)

        super(Certificate, self).delete(*args, **kwargs)


class PkiChangelog(models.Model):
    """Changlog for changes on the PKI. Overrides the builtin admin history"""

    model_id = models.IntegerField()
    object_id = models.IntegerField()
    action_time = models.DateTimeField(auto_now=True)
    action = models.CharField(max_length=64)
    user = models.CharField(max_length=20)
    changes = models.TextField()

    class Meta:
        db_table = "pki_changelog"
        ordering = ["-action_time"]

    def __unicode__(self):
        return str(self.pk)

    def __str__(self):
        return str(self.pk)


class X509Extension(models.Model):
    """X509 extensions"""

    SUBJECT_KEY_IDENTIFIER = (("hash", "hash"),)
    AUTHORITY_KEY_IDENTIFIER = (("keyid:always,issuer:always", "keyid: always, issuer: always"),)
    BASIC_CONSTRAINTS = (
        ("CA:TRUE", "Root or Intermediate CA (CA:TRUE)"),
        ("CA:TRUE, pathlen:0", "Edge CA (CA:TRUE, pathlen:0)"),
        ("CA:FALSE", "Enduser Certificate (CA:FALSE)"),
    )

    name = models.CharField(
        max_length=255,
        unique=True,
        validators=[RegexValidator("[a-zA-Z0-9-_\.]+", message="Name may only contain characters in range a-Z0-9_-.")],
    )
    description = models.CharField(max_length=255)
    created = models.DateTimeField(auto_now_add=True)
    basic_constraints = models.CharField(
        max_length=255,
        choices=BASIC_CONSTRAINTS,
        verbose_name="basicConstraints")
    basic_constraints_critical = models.BooleanField(
        default=True,
        verbose_name="Make basicConstraints critical")
    key_usage = models.ManyToManyField(
        "KeyUsage",
        verbose_name="keyUsage",
        help_text="Usual values:<br />\
                    CA: keyCertSign, cRLsign<br />\
                    Cert: digitalSignature, nonRedupiation, keyEncipherment<br />",
    )
    key_usage_critical = models.BooleanField(
        verbose_name="Make keyUsage critical"
    )
    extended_key_usage = models.ManyToManyField(
        "ExtendedKeyUsage",
        blank=True,
        null=True,
        verbose_name="extendedKeyUsage",
        help_text="serverAuth - SSL/TLS Web Server Authentication<br /> \
                    clientAuth - SSL/TLS Web Client Authentication.<br /> \
                    codeSigning - Code signing<br /> \
                    emailProtection - E-mail Protection (S/MIME)<br /> \
                    timeStamping - Trusted Timestamping<br /> \
                    msCodeInd - Microsoft Individual Code Signing (authenticode)<br /> \
                    msCodeCom - Microsoft Commercial Code Signing (authenticode)<br /> \
                    msCTLSign - Microsoft Trust List Signing<br /> \
                    msSGC - Microsoft Server Gated Crypto<br /> \
                    msEFS - Microsoft Encrypted File System<br /> \
                    nsSGC - Netscape Server Gated Crypto<br />",
    )
    extended_key_usage_critical = models.BooleanField(verbose_name="Make extendedKeyUsage critical")
    subject_key_identifier = models.CharField(
        max_length=255, choices=SUBJECT_KEY_IDENTIFIER, default="hash", verbose_name="subjectKeyIdentifier"
    )
    authority_key_identifier = models.CharField(
        max_length=255,
        choices=AUTHORITY_KEY_IDENTIFIER,
        default="keyid:always,issuer:always",
        verbose_name="authorityKeyIdentifier",
    )
    crl_distribution_point = models.BooleanField(
        verbose_name="Require CRL Distribution Point",
        help_text="All objects using this x509 extension will require a CRLDistributionPoint",
    )

    class Meta:
        db_table = "pki_x509extension"

    def __unicode__(self):
        return self.name

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        """Save the x509 Extension object"""

        if not self.pk:
            super(X509Extension, self).save(*args, **kwargs)
            refresh_pki_metadata(CertificateAuthority.objects.all())

    def crld_point_center(self):
        if self.crl_distribution_point:
            return get_pki_icon_html("icon-yes.gif", "CRL Distribution Point is required", id="crl_dpoint_%d" % self.pk)
        else:
            return get_pki_icon_html(
                "icon-no.gif", "CRL Distribution Points are disabled ", id="crl_dpoint_%d" % self.pk
            )

    crld_point_center.allow_tags = True
    crld_point_center.short_description = "CRL"
    crld_point_center.admin_order_field = "crl_distribution_point"

    def is_ca(self):
        """Return true if this is a CA extension (CA: TRUE)"""

        return "CA:TRUE" in self.basic_constraints.upper()

    def key_usage_csv(self):
        r = []
        if self.key_usage_critical:
            r.append("critical")
        for x in self.key_usage.all():
            r.append(x.name)
        return ",".join(r)

    key_usage_csv.short_description = "Key Usage"

    def ext_key_usage_csv(self):
        r = []
        if self.extended_key_usage_critical:
            r.append("critical")
        for x in self.extended_key_usage.all():
            r.append(x.name)
        return ",".join(r)

    ext_key_usage_csv.short_description = "Extended Key Usage"


class KeyUsage(models.Model):
    """Container table for KeyUsage"""

    name = models.CharField(max_length=64, unique=True)

    def __unicode__(self):
        return self.name

    def __str__(self):
        return self.name


class ExtendedKeyUsage(models.Model):
    """Container table for Extended Key Usage"""

    name = models.CharField(max_length=64, unique=True)

    def __unicode__(self):
        return self.name

    def __str__(self):
        return self.name
