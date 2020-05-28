from django import template
from django.urls import reverse
from django.utils.html import format_html

register = template.Library()

@register.simple_tag
def pkinav():
    return format_html(
        """
        <div id="pkinav">
        <a href="%s">Refresh PKI metadata</a>
        </div>
        """) % reverse('pki:refresh_metadata')
