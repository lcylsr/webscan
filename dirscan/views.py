from django.shortcuts import render

# Create your views here.
def dirscan(request):
    return render(request, 'dirscan.html',{'active':'dirscan'})