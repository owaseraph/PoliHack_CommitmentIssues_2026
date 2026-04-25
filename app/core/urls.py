from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("login/", views.login_view, name="login"),
    path("oauth2callback", views.oauth2callback, name="oauth2callback"),
    path("logout/", views.logout_view, name="logout"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("community/", views.community, name="community"),
    path("community/upvote/<int:report_id>/", views.upvote_report, name="upvote_report"),
    path("download/", views.download, name="download"),
    path("api/scan/", views.api_scan, name="api_scan"),
]
