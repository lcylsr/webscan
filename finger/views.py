from django.shortcuts import render

# Create your views here.
def finger(request):
    return render(request, 'finger.html',{'active':'finger'})