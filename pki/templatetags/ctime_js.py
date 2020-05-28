import time

from django import template

register = template.Library()


@register.simple_tag
def ctime_js():
    return time.time() * 1000
