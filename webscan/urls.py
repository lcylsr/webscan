from django.urls import path
from . import views  # 导入视图函数

app_name = 'webscan'  # 应用命名空间

urlpatterns = [
    path('index/', views.index, name="index"),  # 首页视图
    path('webscan/', views.webscan, name="webscan"),  # 网站扫描视图
    path('webscan-detail/<int:result_id>/', views.webscan_detail, name="webscan_detail"),  # 扫描详情视图，使用scan_id作为URL参数

]
