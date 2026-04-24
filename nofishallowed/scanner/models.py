from django.contrib.auth.models import User
from django.db import models


class PhishingKeyword(models.Model):
    keyword = models.CharField(max_length=512, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['keyword']

    def __str__(self):
        return self.keyword
    
class FlaggedSender(models.Model):
    TYPE_CHOICES = [
        ('email', 'Exact Email'),
        ('domain', 'Domain'),
    ]

    value = models.CharField(max_length=320, unique=True)
    type = models.CharField(max_length=10, choices=TYPE_CHOICES, default='domain')
    reason = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['value']

    def __str__(self):
        return f'[{self.type}] {self.value}'

class EmailScan(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scans')
    initiated_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    emails_scanned = models.IntegerField(default=0)
    phishing_detected = models.IntegerField(default=0)

    class Meta:
        ordering = ['-initiated_at']

    def __str__(self):
        return f'Scan #{self.pk} — {self.user.username} ({self.status})'


class ScannedEmail(models.Model):
    RISK_CHOICES = [
        ('safe', 'Safe'),
        ('phishing', 'Phishing'),
    ]

    scan = models.ForeignKey(EmailScan, on_delete=models.CASCADE, related_name='emails')
    subject = models.TextField(blank=True)
    sender = models.CharField(max_length=320, blank=True)
    body_snippet = models.TextField(blank=True)
    risk = models.CharField(max_length=20, choices=RISK_CHOICES, default='safe')
    matched_keywords = models.JSONField(default=list)
    scanned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-scanned_at']

    def __str__(self):
        return f'[{self.risk.upper()}] {self.subject[:60]}'
    
class CommunityFlag(models.Model):
    TYPE_CHOICES = [
        ('email', 'Exact Email'),
        ('domain', 'Domain'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    submitted_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name='community_flags'
    )
    value = models.CharField(max_length=320)
    type = models.CharField(max_length=10, choices=TYPE_CHOICES, default='domain')
    reason = models.TextField()
    evidence_url = models.URLField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    submitted_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-submitted_at']

    def __str__(self):
        return f'[{self.status}] {self.value} by {self.submitted_by}'