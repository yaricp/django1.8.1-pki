import logging
import os
import random
import shutil
import string
import tempfile
import zipfile

from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.html import format_html
from django.utils.safestring import mark_safe

from . import models
from .settings import PKI_DIR, STATIC_URL

logger = logging.getLogger("pki")


def get_pki_icon_html(img, title="", css="centered", id=""):
    """Return HTML for given image.
        Can add optional alt and title parameters.
        """

    if css:
        css_class = "class=%s" % css
    else:
        css_class = ""

    img_path = os.path.join(STATIC_URL, "img", img)
    return format_html('<img id="%s" %s src="%s" alt="%s" title="%s"/>' % (id, css_class, img_path, title, title))


def get_full_path_file(obj, ext):
    """Return file with ext associated to object.
    """
    subdir = "certs"
    pem = ".pem"
    if ext == "crl":
        subdir = "crl"

    if ext == "cert.p12":
        pem = ""

    if isinstance(obj, models.CertificateAuthority):
        # chain = c_name = obj.name
        ca_dir = os.path.join(PKI_DIR, obj.name)
        # key_loc = os.path.join(ca_dir, "private")
    elif isinstance(obj, models.Certificate):
        if obj.parent:
            # chain = obj.parent.name
            ca_dir = os.path.join(PKI_DIR, obj.parent.name)
        else:
            # chain = obj.name
            ca_dir = os.path.join(PKI_DIR, "_SELF_SIGNED_CERTIFICATES")

        c_name = obj.name
        # key_loc = os.path.join(ca_dir, "certs")
    else:
        raise Exception("Given object type is unknown!")

    return os.path.join(ca_dir, subdir, "%s.%s%s" % (c_name, ext, pem))


def files_for_object(obj):
    """Return files associated to object.
    Return dict containing all files associated to object. Dict contains
    chain, crl, pem, csr, der, pkcs12 and key
    """

    if isinstance(obj, models.CertificateAuthority):
        chain = c_name = obj.name
        ca_dir = os.path.join(PKI_DIR, obj.name)
        key_loc = os.path.join(ca_dir, "private")
    elif isinstance(obj, models.Certificate):
        if obj.parent:
            chain = obj.parent.name
            ca_dir = os.path.join(PKI_DIR, obj.parent.name)
        else:
            chain = obj.name
            ca_dir = os.path.join(PKI_DIR, "_SELF_SIGNED_CERTIFICATES")

        c_name = obj.name
        key_loc = os.path.join(ca_dir, "certs")
    else:
        raise Exception("Given object type is unknown!")

    files = {
        "chain": {"path": os.path.join(ca_dir, "%s-chain.cert.pem" % chain), "name": "%s-chain.cert.pem" % chain,},
        "crl": {"path": os.path.join(ca_dir, "crl", "%s.crl.pem" % chain), "name": "%s.crl.pem" % chain,},
        "pem": {"path": os.path.join(ca_dir, "certs", "%s.cert.pem" % c_name), "name": "%s.cert.pem" % c_name,},
        "csr": {"path": os.path.join(ca_dir, "certs", "%s.csr.pem" % c_name), "name": "%s.csr.pem" % c_name,},
        "der": {"path": os.path.join(ca_dir, "certs", "%s.cert.der" % c_name), "name": "%s.cert.der" % c_name,},
        "pkcs12": {"path": os.path.join(ca_dir, "certs", "%s.cert.p12" % c_name), "name": "%s.cert.p12" % c_name,},
        "key": {"path": os.path.join(ca_dir, key_loc, "%s.key.pem" % c_name), "name": "%s.key.pem" % c_name,},
    }

    return files


def subject_for_object(obj):
    """Return a subject string.
    A OpenSSL compatible subject string is returned.
    """

    subj = "/CN=%s/C=%s/ST=%s/localityName=%s/O=%s" % (
        obj.common_name,
        obj.country,
        obj.state,
        obj.locality,
        obj.organization,
    )

    if obj.OU:
        subj += "/organizationalUnitName=%s" % obj.OU

    if obj.email:
        subj += "/emailAddress=%s" % obj.email

    return subj


def chain_recursion(r_id, store, id_dict):
    """Helper function for recusion"""

    i = models.CertificateAuthority.objects.get(pk=r_id)

    div_content = build_delete_item(i)
    store.append(
        mark_safe(
            'Certificate Authority: <a href="%s">%s</a> <img src="%spki/img/plus.png"'
            ' class="switch" /><div class="details">%s</div>'
            % (reverse("admin:pki_certificateauthority_change", args=(i.pk,)), i.name, STATIC_URL, div_content)
        )
    )

    id_dict["ca"].append(i.pk)

    # Search for child certificates
    child_certs = models.Certificate.objects.filter(parent=r_id)
    if child_certs:
        helper = []
        for cert in child_certs:
            div_content = build_delete_item(cert)
            helper.append(
                mark_safe(
                    'Certificate: <a href="%s">%s</a> <img src="%spki/img/plus.png"'
                    ' class="switch" /><div class="details">%s</div>'
                    % (reverse("admin:pki_certificate_change", args=(cert.pk,)), cert.name, STATIC_URL, div_content)
                )
            )
            id_dict["cert"].append(cert.pk)
        store.append(helper)

    # Search for related CA's
    child_cas = models.CertificateAuthority.objects.filter(parent=r_id)
    if child_cas:
        helper = []
        for ca in child_cas:
            chain_recursion(ca.pk, helper, id_dict)
        store.append(helper)


def build_delete_item(obj):
    """Build div tag for delete details"""

    parent = "None"
    if obj.parent is not None:
        parent = obj.parent.name

    return (
        "<ul><li>Serial: %s</li><li>Subject: %s</li><li>Parent: %s</li><li>Description: %s</li>"
        "<li>x509 Extension: %s</li><li>Created: %s</li><li>Expiry date: %s</li></ul>"
        % (obj.serial, subject_for_object(obj), parent, obj.description, obj.extension, obj.created, obj.expiry_date)
    )


def generate_temp_file():
    """Generate a filename in the systems temp directory"""

    f = os.path.join(tempfile.gettempdir(), "".join(random.sample(string.ascii_letters + string.digits, 25)))

    if os.path.exists(f):
        raise Exception("The generated temp file %s already exists!" % f)

    return f


def build_zip_for_object(obj):
    """Build zip with filed ob object."""

    try:
        # base_folder = "PKI_DATA_%s" % obj.name
        files = files_for_object(obj)
        zip_f = generate_temp_file()

        c_zip = zipfile.ZipFile(zip_f, "w")

        c_zip.write(files["key"]["path"], files["key"]["name"])
        c_zip.write(files["pem"]["path"], files["pem"]["name"])

        if isinstance(obj, models.CertificateAuthority) or obj.parent:
            c_zip.write(files["chain"]["path"], files["chain"]["name"])
            c_zip.write(files["crl"]["path"], files["crl"]["name"])

        try:
            if obj.pkcs12_encoded:
                c_zip.write(files["pkcs12"]["path"], files["pkcs12"]["name"])
        except AttributeError:
            pass

        if obj.der_encoded:
            c_zip.write(files["der"]["path"], files["der"]["name"])

        c_zip.close()
    except Exception as e:
        logger.error("Exception during zip file creation: %s" % e)
        raise Exception(e)

    return zip_f


def get_files_for_vpn_server(username: str, hostname: str, path_file: str, parent_passphrase: str = None) -> None:
    """ Get files for VPN server"""
    try:
        obj = models.Certificate.objects.get(name=hostname)
    except models.Certificate.DoesNotExist:
        extension = models.x509Extension.objects.get(name="v3_edge_cert_server")
        parent = models.CertificateAuthority.objects.first()
        if parent_passphrase:
            obj = models.Certificate(
                common_name=hostname,
                name=hostname,
                extension=extension,
                parent=parent,
                user=username,
                parent_passphrase=parent_passphrase,
            )
            obj.save()
        else:
            return "needs parent_passphrase!"
    files = files_for_object(obj)
    path_ca = files["pem"]["path"].replace(files["pem"]["name"], "")
    name_ca = files["chain"]["name"].replace("-chain", "")
    ca_name = os.path.join(path_ca, name_ca)
    shutil.copy(ca_name, os.path.join(path_file, "ca.crt"))
    key_name_file = files["key"]["path"]
    shutil.copy(key_name_file, os.path.join(path_file, "server.key"))
    pem_name_file = files["pem"]["path"]
    shutil.copy(pem_name_file, os.path.join(path_file, "server.crt"))


def get_files_for_vpn_client(
    username: str,
    nameclient: str,
    servers: list,
    port: int,
    dev: str,
    proto: str,
    cipher: str,
    lzo: bool,
    ta: str,
    parent_passphrase: str = None,
) -> None:
    """Get config files for VPN clients"""
    cfg = {"servers": servers, "port": port, "dev": dev, "proto": proto, "cipher": cipher, "lzo": lzo, "ta": ta}
    try:
        obj = models.Certificate.objects.get(name=nameclient)
    except models.Certificate.DoesNotExist:
        extension = models.x509Extension.objects.get(name="v3_edge_cert_client")
        parent = models.CertificateAuthority.objects.first()
        if parent_passphrase:
            obj = models.Certificate(
                common_name=nameclient,
                name=nameclient,
                extension=extension,
                parent=parent,
                user=username,
                parent_passphrase=parent_passphrase,
            )
            obj.save()
        else:
            return "needs parent_passphrase!"
        print("created client cert: ", obj)
    file = build_ovpn_for_object(obj, cfg)
    return file


def build_ovpn_for_object(obj, cfg: dict = None):
    """Prepare config file for openVPN server or client."""
    if not (obj.extension.name.find("client") != -1):
        return None
    if not cfg:
        print("not")
        cfg = {"servers": "", "port": "", "dev": "", "proto": "", "cipher": "", "lzo": "", "ta": ""}
    files = files_for_object(obj)
    ca_path_file = os.path.join(PKI_DIR, obj.parent.name, "certs", "%s.cert.pem" % obj.parent.name)
    with open(ca_path_file, "r") as file:
        ca = file.read()
    with open(os.path.join(files["key"]["path"]), "r") as file:
        key = file.read()
    with open(os.path.join(files["pem"]["path"]), "r") as file:
        pem_text = file.read()
        pem = "-----BEGIN CERTIFICATE-----\n" + pem_text.split("-----BEGIN CERTIFICATE-----")[1]
    cfg.update(
        {"ca": ca, "key": key, "pem": pem,}
    )
    ovpn_f = generate_temp_file()
    print("sfg.servres: ", cfg["servers"])
    ovpn_text = render_to_string("ovpn.tpl", cfg)
    with open(ovpn_f, "w") as file:
        file.write(ovpn_text)
    return ovpn_f
