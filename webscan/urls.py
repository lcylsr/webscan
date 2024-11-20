from django.urls import path
from . import views  # 导入视图函数

app_name = 'webscan'  # 应用命名空间

urlpatterns = [
    path('index/', views.index, name="index"),  # 首页视图
    path('webscan/', views.webscan, name="webscan"),  # 网站扫描视图
    path('webscan-progress/', views.webscan_progress, name="webscan_progress"),  # 网站扫描进度视图
    path('webscan-detail/<uuid:scan_task_id>', views.webscan_detail, name="webscan_detail"),  # 网站扫描详情视图
    path('webscan-detail_info/', views.webscan_detail_info, name="webscan_detail_info"),  # 网站扫描详情信息视图
    path('webscan_report/', views.webscan_report, name="webscan_report"),  # 网站扫描报告视图
    path('get_running_scan_task_id/', views.get_running_scan_task_id, name="get_running_scan_task_id")  # 获取正在运行的扫描任务ID视图

]
