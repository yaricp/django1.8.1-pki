from pki import __version__ as version

from django import template

register = template.Library()


@register.simple_tag
def pki_version():
    return version
