from celery.worker.control import active
from django.shortcuts import render

# Create your views here.
def login(request):
    return render(request, 'webauth/login.html')

def register(request):
    return render(request, 'webauth/register.html')

def forgot(request):
    return render(request, 'webauth/forgot.html')

def selfdata(request):
    return render(request, 'webauth/selfdata.html',{'active':'selfdata'})

def settings(request):
    return render(request, 'webauth/settings.html',{'active':'settings'})

