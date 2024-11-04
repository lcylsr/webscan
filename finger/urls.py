from  . import views
from django.urls import path
    
app_name = 'finger'

urlpatterns = [
    path('',views.finger,name="finger"),


]
