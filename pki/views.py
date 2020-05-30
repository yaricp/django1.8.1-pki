# coding=utf-8
import logging
import os

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils.safestring import mark_safe

from .email import send_certificate_data
from .forms import DeleteForm
from .graphviz import object_chain, object_tree
from .helper import (
    build_delete_item,
    build_ovpn_for_object,
    build_zip_for_object,
    chain_recursion,
    generate_temp_file,
    get_full_path_file,
)
from .models import Certificate, CertificateAuthority, X509Extension
from .openssl import refresh_pki_metadata
from .settings import PKI_ENABLE_EMAIL, PKI_ENABLE_GRAPHVIZ, PKI_LOG, STATIC_URL

logger = logging.getLogger("pki")


@login_required
def home_page(request):
    certs = CertificateAuthority.objects.filter(public=True, active=True)
    personal_certs_all = Certificate.objects.filter(user=request.user.username)
    personal_certs = [c for c in personal_certs_all if not c.is_server_side_cert]
    return render(request, "home.html", {"certs": certs, "personal_certs": personal_certs,})


def pki_download(request, model, id, ext):
    """
    Download files (zip or crl or cert or p12).
    """
    if model == "certificateauthority":
        c = get_object_or_404(CertificateAuthority, pk=id, public=True)
    elif model == "certificate":
        if request.user.is_authenticated:
            c = get_object_or_404(Certificate, pk=id)
            if not request.user.has_perm("pki.can_download"):
                messages.error(request, "Permission denied!")
                return HttpResponseRedirect(reverse("admin:pki_%s_changelist" % model))
        else:
            return HttpResponseRedirect(reverse("accounts:login"))
    else:
        logger.error("Unsupported type %s requested!" % type)
        return HttpResponseBadRequest()

    if not c.active:
        raise Http404
    print("C: ", c)
    if ext == "zip":
        file = build_zip_for_object(c)
    elif ext == "ovpn":
        file = build_ovpn_for_object(c)
    elif ext == "crl":
        file = get_full_path_file(c, ext="crl")
    elif ext == "crt":
        file = get_full_path_file(c, ext="cert")
    elif ext == "p12":
        file = get_full_path_file(c, ext="cert.p12")
    # open and read the file if it exists
    print("FILE:" + str(file))

    if os.path.exists(file):
        if ext == "zip":
            zip_file = open(file, "rb")
        else:
            zip_file = open(file, "r")
        if ext == "ovpn":
            file = "client.ovpn"
        response = HttpResponse(zip_file, content_type="application/force-download")
        response["Content-Disposition"] = 'attachment; filename="%s"' % file
        return response
    else:
        logger.error("File not found: %s" % file)
        raise Http404


#
# @login_required
# def pki_download_crt(request, model, id):
#    """
#    Download Certificate.
#
#    """
#
#    if not request.user.has_perm('pki.can_download'):
#        messages.error(request, "Permission denied!")
#        return HttpResponseRedirect(urlresolvers.reverse('admin:pki_%s_changelist' % model))
#
#    if model == "certificateauthority":
#        c = get_object_or_404(CertificateAuthority, pk=id)
#    elif model == "certificate":
#        c = get_object_or_404(Certificate, pk=id)
#    else:
#        logger.error( "Unsupported type %s requested!" % type )
#        return HttpResponseBadRequest()
#
#    if not c.active:
#        raise Http404
#
#    file_crt = get_full_path_file(c, ext='cert')
#
#    ## open and read the file if it exists
#    if os.path.exists(file_crt):
#        f = open(file_crt)
#        x = f.readlines()
#        f.close()
#
#        ## return the HTTP response
#        response = HttpResponse(x, content_type='application/force-download')
#        #response['Content-Disposition'] = 'attachment; filename="PKI_DATA_%s.zip"' % c.name
#        response['Content-Disposition'] = 'attachment; filename="%s.crt"' % c.name
#
#        return response
#    else:
#        logger.error( "File not found: %s" % file_crt )
#        raise Http404
#
#
#
# @login_required
# def pki_download_zip(request, model, id):
#    """Download PKI data.
#
#    Type (ca/cert) and ID are used to determine the object to download.
#    """
#
#    if not request.user.has_perm('pki.can_download'):
#        messages.error(request, "Permission denied!")
#        return HttpResponseRedirect(urlresolvers.reverse('admin:pki_%s_changelist' % model))
#
#    if model == "certificateauthority":
#        c = get_object_or_404(CertificateAuthority, pk=id)
#    elif model == "certificate":
#        c = get_object_or_404(Certificate, pk=id)
#    else:
#        logger.error( "Unsupported type %s requested!" % type )
#        return HttpResponseBadRequest()
#
#    if not c.active:
#        raise Http404
#
#    zip = build_zip_for_object(c)
#
#    ## open and read the file if it exists
#    if os.path.exists(zip):
#        f = open(zip)
#        x = f.readlines()
#        f.close()
#
#        ## return the HTTP response
#        response = HttpResponse(x, content_type='application/force-download')
#        #response['Content-Disposition'] = 'attachment; filename="PKI_DATA_%s.zip"' % c.name
#        response['Content-Disposition'] = 'attachment; filename="%s.zip"' % c.name
#
#        return response
#    else:
#        logger.error( "File not found: %s" % zip )
#        raise Http404


@login_required
def pki_chain(request, model, id):
    """Display the CA chain as PNG.
    Requires PKI_ENABLE_GRAPHVIZ set to true. Type (ca/cert) and ID are used to determine the object.
    Create object chain PNG using graphviz and return it to the user.
    """

    if PKI_ENABLE_GRAPHVIZ is not True:
        messages.warning(request, "Chain view is disabled unless setting PKI_ENABLE_GRAPHVIZ is set to True")
        return HttpResponseRedirect(reverse("admin:pki_%s_changelist" % model))

    if model == "certificateauthority":
        obj = get_object_or_404(CertificateAuthority, pk=id)
    elif model == "certificate":
        obj = get_object_or_404(Certificate, pk=id)

    png = generate_temp_file()
    object_chain(obj, png)

    try:
        if os.path.exists(png):
            f = open(png, "rb")
            x = f.read()
            f.close()
            os.remove(png)
    except OSError as e:
        logger.error("Failed to load depency tree: %s" % e)
        raise Exception(e)

    response = HttpResponse(x, content_type="image/png")
    return response


@login_required
def pki_tree(request, id):
    """Display the CA tree as PNG.
    Requires PKI_ENABLE_GRAPHVIZ set to true. Only works for Certificate Authorities.
    All object related to the CA obj are fetched and displayed in a Graphviz tree.
    """

    if PKI_ENABLE_GRAPHVIZ is not True:
        messages.warning(request, "Tree view is disabled unless setting PKI_ENABLE_GRAPHVIZ is set to True")
        return HttpResponseRedirect(reverse("admin:pki_certificateauthority_changelist"))

    obj = get_object_or_404(CertificateAuthority, pk=id)
    png = generate_temp_file()

    object_tree(obj, png)

    try:
        if os.path.exists(png):
            f = open(png, "rb")
            x = f.read()
            f.close()

            os.remove(png)
    except OSError as e:
        logger.error("Failed to load depency tree: %s" % e)
        raise Exception(e)

    response = HttpResponse(x, content_type="image/png")
    return response


@login_required
def pki_email(request, model, id):
    """Send email with certificate data attached.
    Requires PKI_ENABLE_EMAIL set to true. Type (ca/cert) and ID are used to determine the object.
    Build ZIP, send email and return to changelist.
    """

    if PKI_ENABLE_EMAIL is not True:
        messages.warning(request, "Email delivery is disabled unless setting PKI_ENABLE_EMAIL is set to True")
        return HttpResponseRedirect(reverse("admin:pki_%s_changelist" % model))

    if model == "certificateauthority":
        obj = get_object_or_404(CertificateAuthority, pk=id)
    elif model == "certificate":
        obj = get_object_or_404(Certificate, pk=id)

    if obj.email and obj.active:
        send_certificate_data(obj, request)
    else:
        raise Http404

    messages.info(request, 'Email to "%s" was sent successfully.' % obj.email)
    return HttpResponseRedirect(reverse("admin:pki_%s_changelist" % model))


@login_required
def pki_refresh_metadata(request):
    """Rebuild PKI metadate.
    Renders openssl.conf template and cleans PKI_DIR.
    """

    ca_objects = list(CertificateAuthority.objects.all())
    refresh_pki_metadata(ca_objects)
    messages.info(request, "Successfully refreshed PKI metadata (%d certificate authorities)" % len(ca_objects))

    back = request.META.get("HTTP_REFERER", None) or "/admin"
    return HttpResponseRedirect(back)


@login_required
def admin_history(request, model, id):
    """Overwrite the default admin history view"""

    from django.contrib.contenttypes.models import ContentType
    from pki.models import PkiChangelog

    ct = ContentType.objects.get(model=model)
    model_obj = ct.model_class()
    obj = model_obj.objects.get(pk=id)
    if model == "certificate":
        opts = Certificate._meta
    elif model == "certificateauthority":
        opts = CertificateAuthority._meta
    elif model == "x509Extension":
        opts = X509Extension._meta

    changelogs = PkiChangelog.objects.filter(model_id=ct.pk).filter(object_id=id)
    return render(
        request,
        "admin/pki/object_changelogs.html",
        {
            "changelogs": changelogs,
            "opts": opts,
            "title": "Change history: %s" % obj.common_name,
            "app_label": model_obj._meta.app_label,
            "object": obj,
            "model_name": model,
        },
    )


@login_required
def admin_delete(request, model, id):
    """Overwite the default admin delete view"""

    deleted_objects = []
    parent_object_name = CertificateAuthority._meta.verbose_name
    title = "Are you sure?"

    if model == "certificateauthority":

        item = get_object_or_404(CertificateAuthority, pk=id)
        chain_recursion(item.id, deleted_objects, id_dict={"cert": [], "ca": [],})

        opts = CertificateAuthority._meta
        object = item.name
        # initial_id = False

        if item.parent_id:
            # initial_id = item.parent_id
            auth_object = CertificateAuthority.objects.get(pk=item.parent_id).name
        else:
            # initial_id = item.pk
            auth_object = item.name
    elif model == "certificate":
        try:
            item = Certificate.objects.select_related().get(pk=id)
        except Exception:
            raise Http404

        if not item.parent_id:
            parent_object_name = "self-signed certificate"
            # initial_id = item.id
            authentication_obj = item.name
        else:
            # initial_id = item.parent_id
            authentication_obj = item.parent.name

        div_content = build_delete_item(item)
        deleted_objects.append(
            mark_safe(
                'Certificate: <a href="%s">%s</a> <img src="%spki/img/plus.png" class="switch" />'
                '<div class="details">%s</div>'
                % (reverse("admin:pki_certificate_change", args=(item.pk,)), item.name, STATIC_URL, div_content)
            )
        )

        # Fill the required data for delete_confirmation.html template
        opts = Certificate._meta
        object = item.name

        # Set the CA to verify the passphrase against
        auth_object = authentication_obj

    if request.method == "POST":
        form = DeleteForm(request.POST)

        if form.is_valid():
            item.delete(request.POST["passphrase"])
            messages.info(request, 'The %s "%s" was deleted successfully.' % (opts.verbose_name, object))
            return HttpResponseRedirect(reverse("admin:pki_%s_changelist" % model))
    else:
        form = DeleteForm()

        form.fields["_model"].initial = model
        form.fields["_id"].initial = id
    return render(
        request,
        "admin/pki/delete_confirmation.html",
        {
            "deleted_objects": deleted_objects,
            "object_name": opts.verbose_name,
            "opts": opts,
            "object": item,
            "object_id": item.pk,
            "form": form,
            "auth_object": auth_object,
            "parent_object_name": parent_object_name,
            "title": title,
        },
    )


@login_required
def show_exception(request):
    """Render error page and fill it with the PKI_LOG content"""

    f = open(PKI_LOG, "r")
    log = f.readlines()
    f.close()

    return render("500.html", request, {"log": log})
