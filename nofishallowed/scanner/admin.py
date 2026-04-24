from django.contrib import admin
from django.utils import timezone

from .models import CommunityFlag, EmailScan, FlaggedSender, PhishingKeyword, ScannedEmail


@admin.register(PhishingKeyword)
class PhishingKeywordAdmin(admin.ModelAdmin):
    list_display = ('keyword', 'is_active', 'created_at')
    list_filter = ('is_active',)
    search_fields = ('keyword',)


@admin.register(EmailScan)
class EmailScanAdmin(admin.ModelAdmin):
    list_display = ('pk', 'user', 'status', 'emails_scanned', 'phishing_detected', 'initiated_at')
    readonly_fields = ('initiated_at', 'completed_at')


@admin.register(ScannedEmail)
class ScannedEmailAdmin(admin.ModelAdmin):
    list_display = ('subject', 'sender', 'risk', 'scanned_at')
    list_filter = ('risk',)


@admin.register(FlaggedSender)
class FlaggedSenderAdmin(admin.ModelAdmin):
    list_display = ('value', 'type', 'reason', 'is_active', 'created_at')
    list_filter = ('type', 'is_active')
    search_fields = ('value', 'reason')


@admin.register(CommunityFlag)
class CommunityFlagAdmin(admin.ModelAdmin):
    list_display = ('value', 'type', 'submitted_by', 'status', 'submitted_at')
    list_filter = ('status', 'type')
    actions = ['approve_flags']

    def approve_flags(self, request, queryset):
        for flag in queryset.filter(status='pending'):
            FlaggedSender.objects.get_or_create(
                value=flag.value,
                defaults={'type': flag.type, 'reason': flag.reason},
            )
            flag.status = 'approved'
            flag.reviewed_at = timezone.now()
            flag.save()
        self.message_user(request, f'{queryset.count()} flag(s) approved and added to blocklist.')
    approve_flags.short_description = 'Approve selected flags → add to blocklist'
    approve_flags.short_description = 'Approve selected flags → add to blocklist'