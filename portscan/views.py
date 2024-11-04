from django.shortcuts import render

# Create your views here.
def portscan(request):
    return render(request, 'portscan.html',{'active':'portscan'})