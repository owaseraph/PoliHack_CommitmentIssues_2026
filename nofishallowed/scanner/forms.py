from django import forms


class ManualScanForm(forms.Form):
    subject = forms.CharField(
        max_length=998, required=False, label='Subject',
        widget=forms.TextInput(attrs={'placeholder': 'Email subject…'}),
    )
    sender = forms.CharField(
        max_length=320, required=False, label='Sender',
        widget=forms.TextInput(attrs={'placeholder': 'sender@example.com'}),
    )
    body = forms.CharField(
        required=False, label='Body',
        widget=forms.Textarea(attrs={'rows': 8, 'placeholder': 'Paste email body here…'}),
    )

from .models import CommunityFlag

class CommunityFlagForm(forms.Form):
    type = forms.ChoiceField(
        choices=[('domain', 'Domain'), ('email', 'Exact Email')],
        label='Type',
    )
    value = forms.CharField(
        max_length=320, label='Domain or Email',
        widget=forms.TextInput(attrs={'placeholder': 'e.g. evil-phish.com or scam@fake.com'}),
    )
    reason = forms.CharField(
        label='Why is this suspicious?',
        widget=forms.Textarea(attrs={'rows': 3, 'placeholder': 'Describe the phishing attempt…'}),
    )
    evidence_url = forms.URLField(
        required=False, label='Evidence URL (optional)',
        widget=forms.TextInput(attrs={'placeholder': 'https://…'}),
    )