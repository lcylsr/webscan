from  . import views
from django.urls import path
    
app_name = 'webauth'

urlpatterns = [
    path("login",views.login,name="login"),
    path("register",views.register,name="register"),
    path("forgot",views.forgot,name="forgot"),
    path("selfdata",views.selfdata,name="selfdata"),
    path("settings",views.settings,name="settings" ),

]
