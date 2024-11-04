from  . import views
from django.urls import path
    
app_name = 'dirscan'

urlpatterns = [
    path('dirscan',views.dirscan,name="dirscan"),

]
