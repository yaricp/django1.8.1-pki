import os
from hashlib import md5 as md5

from django import forms
from django.forms.utils import ErrorList
from django.http import Http404
from django.shortcuts import get_object_or_404

from .models import Certificate, CertificateAuthority, X509Extension
from .settings import PKI_CA_NAME_BLACKLIST, PKI_DIR


class CertificateAuthorityForm(forms.ModelForm):
    """Validation class for CertificateAuthority form"""

    passphrase = forms.CharField(widget=forms.PasswordInput)
    passphrase_verify = forms.CharField(widget=forms.PasswordInput, required=False)
    parent_passphrase = forms.CharField(widget=forms.PasswordInput, required=False)

    class Meta:
        model = CertificateAuthority
        fields = "__all__"

    def clean(self):
        """Verify fields"""

        cleaned_data = self.cleaned_data

        name = cleaned_data.get("name")
        action = cleaned_data.get("action")
        parent = cleaned_data.get("parent")
        pf = cleaned_data.get("passphrase")
        pf_v = cleaned_data.get("passphrase_verify")
        p_pf = cleaned_data.get("parent_passphrase")
        extension = cleaned_data.get("extension")
        crl_dpoints = cleaned_data.get("crl_dpoints")

        enc_p_pf = None

        if name in PKI_CA_NAME_BLACKLIST:
            self._errors["name"] = ErrorList(['Name "%s" is blacklisted!' % name])
            return cleaned_data

        if action in ("create", "renew"):
            if action == "create":
                if not pf_v or pf != pf_v:
                    self.errors["passphrase_verify"] = ErrorList(["Passphrase mismtach!"])

                # Verify that we're not creating a certificate that already exists
                if name and os.path.isdir(os.path.join(PKI_DIR, name)):
                    self._errors["name"] = ErrorList(['Name "%s" is already in use!' % name])

            # Take care that parent is active when action is revoke
            if action == "renew":
                ca = CertificateAuthority.objects.get(name="%s" % name)

                # Prevent renewal when parent is disabled
                if ca.parent is not None and ca.parent.active is not True:
                    self._errors["action"] = ErrorList(
                        ['Cannot renew CA certificate when parent "%s" isn\'t active!' % ca.parent.name]
                    )
                    return cleaned_data

                # Compare passphrase
                if not pf or (ca.passphrase != md5(pf).hexdigest()):
                    self._errors["passphrase"] = ErrorList(
                        ['Passphrase is wrong. Enter correct passphrase for CA "%s"' % cleaned_data.get("common_name")]
                    )

            if parent:
                ca = CertificateAuthority.objects.get(name="%s" % parent.name)
                if p_pf:
                    enc_p_pf = md5(p_pf).hexdigest()

                # Check if parent allows sub CA
                if ca.is_edge_ca():
                    self._errors["parent"] = ErrorList(
                        ["Parent's x509 extension doesn't allow a sub CA. Only non CA certificates can be created"]
                    )

                # Check parent passphrase if not RootCA
                if ca.passphrase != enc_p_pf:
                    self._errors["parent_passphrase"] = ErrorList(
                        ['Passphrase is wrong. Enter correct passphrase for CA "%s"' % parent]
                    )

            # Verify CRL distribution settings
            x509 = get_object_or_404(X509Extension, name=extension)
            if x509.crl_distribution_point and not crl_dpoints:
                self._errors["crl_dpoints"] = ErrorList(
                    ['CRL Distribution Points are required by x509 extension "%s"' % extension]
                )
        elif action == "revoke":
            if parent:
                ca = CertificateAuthority.objects.get(name="%s" % parent.name)
                enc_p_pf = md5(cleaned_data.get("parent_passphrase")).hexdigest()

                # Check parent passphrase
                if ca.passphrase != enc_p_pf:
                    self._errors["parent_passphrase"] = ErrorList(
                        ['Passphrase is wrong. Enter correct passphrase for CA "%s"' % parent]
                    )
            else:
                self._errors["action"] = ErrorList(
                    [
                        "You cannot revoke a self-signed root certificate as there"
                        "s no CA to revoke against. Delete it instead!"
                    ]
                )

        return cleaned_data


class CertificateForm(forms.ModelForm):
    """Validation class for Certificate form"""

    passphrase = forms.CharField(widget=forms.PasswordInput, required=False)
    passphrase_verify = forms.CharField(widget=forms.PasswordInput, required=False)
    parent_passphrase = forms.CharField(widget=forms.PasswordInput, required=False)
    pkcs12_passphrase = forms.CharField(widget=forms.PasswordInput, required=False)
    pkcs12_passphrase_verify = forms.CharField(widget=forms.PasswordInput, required=False)

    class Meta:
        model = Certificate
        fields = "__all__"

    def clean(self):
        """Verify crucial fields"""

        cleaned_data = self.cleaned_data

        name = cleaned_data.get("name")
        action = cleaned_data.get("action")
        parent = cleaned_data.get("parent")
        pf = cleaned_data.get("passphrase")
        pf_v = cleaned_data.get("passphrase_verify")
        p_pf = cleaned_data.get("parent_passphrase")
        extension = cleaned_data.get("extension")
        crl_dpoints = cleaned_data.get("crl_dpoints")

        enc_p_pf = None

        if action in ("create", "renew"):
            if action == "create":
                if (pf and not pf_v) or pf != pf_v:
                    self.errors["passphrase_verify"] = ErrorList(["Passphrase mismtach detected"])

                # Verify that we're not creating a certificate that already exists
                if parent:
                    if os.path.exists(os.path.join(PKI_DIR, parent.name, "certs", "%s.key.pem" % name)):
                        self._errors["name"] = ErrorList(['Name "%s" is already in use!' % name])
                else:
                    if os.path.exists(os.path.join(PKI_DIR, "_SELF_SIGNED_CERTIFICATES", "certs", "%s.key.pem" % name)):
                        self._errors["name"] = ErrorList(['Name "%s" is already in use!' % name])

            # Take care that parent is active when action is revoke
            if action == "renew":
                cert = Certificate.objects.get(name="%s" % name)

                if cert.parent is not None and cert.parent.active is not True:
                    self._errors["action"] = ErrorList(
                        ['Cannot renew certificate when parent CA "%s" isn\'t active!' % cert.parent]
                    )
                    return cleaned_data

            if parent:
                ca = CertificateAuthority.objects.get(name="%s" % parent.name)
                if p_pf:
                    enc_p_pf = md5(p_pf.encode("utf-8")).hexdigest()

                # Check parent passphrase
                if ca.passphrase != enc_p_pf:
                    self._errors["parent_passphrase"] = ErrorList(
                        ['Passphrase is wrong. Enter correct passphrase for CA "%s"' % parent]
                    )

            # Verify CRL distribution settings
            x509 = get_object_or_404(X509Extension, name=extension)
            if x509.crl_distribution_point and not crl_dpoints:
                self._errors["crl_dpoints"] = ErrorList(
                    ['CRL Distribution Points are required by x509 extension "%s"' % extension]
                )
        elif action == "revoke":
            if parent:
                ca = CertificateAuthority.objects.get(name="%s" % parent.name)
                if p_pf:
                    enc_p_pf = md5(p_pf).hexdigest()

                # Check parent passphrase
                if ca.passphrase != enc_p_pf:
                    self._errors["parent_passphrase"] = ErrorList(
                        ['Passphrase is wrong. Enter correct passphrase for CA "%s"' % parent]
                    )
            else:
                self._errors["action"] = ErrorList(
                    [
                        "You cannot revoke a self-signed certificate as there's"
                        " no CA to revoke against. Delete it instead!"
                    ]
                )

        return cleaned_data


class X509ExtensionForm(forms.ModelForm):
    """Validation class for x590 Extensions form"""

    class Meta:
        model = X509Extension
        fields = "__all__"

    def clean(self):
        """Verify crucial fields"""

        cleaned_data = self.cleaned_data

        # name = cleaned_data.get("name")
        bc = cleaned_data.get("basic_constraints")
        # ku = cleaned_data.get("key_usage")
        eku = cleaned_data.get("extended_key_usage")
        eku_c = cleaned_data.get("extended_key_usage_critical")

        if bc in ("root_ca", "edge_ca"):
            if len(eku) > 0:
                self._errors["extended_key_usage"] = ErrorList(["You cannot set extendedKeyUsage for a CA extension"])
            if eku_c is True:
                self._errors["extended_key_usage_critical"] = ErrorList(
                    ["You cannot set extendedKeyUsage to critical for a CA extension"]
                )
        elif bc == "enduser_cert":
            if len(eku) < 1:
                self._errors["extended_key_usage"] = ErrorList(["extendedKeyUsage is required for a non-CA extension"])

        return cleaned_data


class DeleteForm(forms.Form):
    """Deletion form base class"""

    _model = forms.CharField(widget=forms.HiddenInput, required=True)
    _id = forms.CharField(widget=forms.HiddenInput, required=True)
    passphrase = forms.CharField(max_length=100, widget=forms.PasswordInput, required=False)

    def clean(self):
        """Let's veridfy the given passphrase"""

        cleaned_data = self.cleaned_data
        model = cleaned_data.get("_model")
        obj_id = cleaned_data.get("_id")
        pf_raw = cleaned_data.get("passphrase")

        if not pf_raw or pf_raw == "":
            pf_in = ""
        else:
            # print(pf_raw.decode('utf8'))
            pf_in = md5(pf_raw.encode("utf-8")).hexdigest()

        print(model)
        if model == "certificateauthority":
            obj = get_object_or_404(CertificateAuthority, pk=obj_id)

            if not pf_in or pf_in == "":
                self._errors["passphrase"] = ErrorList(["Passphrase is missing!"])
                return cleaned_data
        elif model == "certificate":
            obj = get_object_or_404(Certificate, pk=obj_id)

            if not obj.parent and not obj.passphrase:
                return cleaned_data
        else:
            raise Http404

        if obj.parent:
            pf_obj = obj.parent.passphrase
        else:
            pf_obj = obj.passphrase

        if pf_in != pf_obj:
            self._errors["passphrase"] = ErrorList(["Passphrase is wrong!"])

        return cleaned_data
