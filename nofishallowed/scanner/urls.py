from django.urls import path
from . import views

urlpatterns = [
    path('scan/', views.scan_view, name='scan'),
    path('history/', views.history_view, name='history'),
    path('community/', views.community_list, name='community'),
    path('community/flag/', views.community_flag, name='community_flag'),
    path('community/my-flags/', views.community_my_flags, name='community_my_flags'),
]