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
    # Marketplace
    path("marketplace/", views.marketplace, name="marketplace"),
    path("marketplace/install/<int:plugin_id>/", views.marketplace_install, name="marketplace_install"),
    path("marketplace/toggle/<int:plugin_id>/", views.marketplace_toggle, name="marketplace_toggle"),
    path("marketplace/upvote/<int:plugin_id>/", views.marketplace_upvote, name="marketplace_upvote"),
    path("marketplace/create/", views.plugin_create, name="plugin_create"),
    path("marketplace/mine/", views.my_plugins, name="my_plugins"),
]
