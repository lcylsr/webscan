from  . import views
from django.urls import path
    
app_name = 'portscan'

urlpatterns = [
    path('',views.portscan,name="portscan"),

]
