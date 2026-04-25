from django.contrib import admin
from .models import UserToken, CommunityReport


@admin.register(CommunityReport)
class CommunityReportAdmin(admin.ModelAdmin):
    list_display = ["title", "sender_email", "reported_by", "created_at", "upvotes"]
    list_filter = ["created_at"]
    search_fields = ["title", "sender_email", "description"]
    ordering = ["-created_at"]


@admin.register(UserToken)
class UserTokenAdmin(admin.ModelAdmin):
    list_display = ["user_id"]
    search_fields = ["user_id"]
