# coding=utf-8
import hmac
import binascii
from hashlib import sha512

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.contrib.auth.models import User
from django.contrib import auth
from django.utils.translation import ugettext_lazy as _

def get_login_parameters(request):
    if request.GET:
        username = request.GET['username']
        next = request.GET['next']
        token = request.GET['token']
        datetime = request.GET['datetime']
    else:
        username = request.POST['username']
        next = request.POST['next']
        token = request.POST['token']
        datetime = request.POST['datetime']
    return username,  next,  datetime,  token 

def login(request):
    username, next, datetime,  token = get_login_parameters(request)
    string_token = username+str(len(username))+next+str(len(next))+datetime+str(len(datetime))
    hashed = hmac.new(binascii.a2b_hex(settings.AUTH_CENTER_KEY), string_token, sha512)
    my_token = hashed.hexdigest().upper()
    if next == '':
        next=settings.AUTH_CENTER_DEFAULT_LOGIN_URL_REDIRECT
    if my_token != token:
        return  render_to_response('error_auth.html', {'mess':_('WHO ARE YOU? I DON`T KNOW YOU!')})
    try:
        user = User.objects.get(username=username)
    except:
        user = None
    if user:
        user=auth.authenticate(username=user.username, password=settings.AUTH_CENTER_PASSWORD)
    else:
        user = User.objects.create_user(username, '', settings.AUTH_CENTER_PASSWORD)
    auth.login(request, user)
    request.session.set_expiry(settings.AUTH_CENTER_LENGHT_SESSION)
    return HttpResponseRedirect(next)
            
    
def logout(request):
    auth.logout(request)
    return HttpResponseRedirect(settings.AUTH_CENTER_LOGOUT_URL_REDIRECT)
    
