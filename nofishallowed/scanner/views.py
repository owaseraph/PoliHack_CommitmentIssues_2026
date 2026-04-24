from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.utils import timezone

from .detection import analyse_email
from .forms import CommunityFlagForm, ManualScanForm
from .models import CommunityFlag, EmailScan, FlaggedSender, ScannedEmail


@login_required
def scan_view(request):
    form = ManualScanForm(request.POST or None)
    result = None

    if request.method == 'POST' and form.is_valid():
        subject = form.cleaned_data['subject']
        sender = form.cleaned_data['sender']
        body = form.cleaned_data['body']

        scan = EmailScan.objects.create(user=request.user, status='pending')
        detection = analyse_email(subject, body, sender)

        ScannedEmail.objects.create(
            scan=scan,
            subject=subject,
            sender=sender,
            body_snippet=body[:500],
            risk=detection['risk'],
            matched_keywords=detection['matched_keywords'],
        )

        scan.emails_scanned = 1
        scan.phishing_detected = 1 if detection['risk'] == 'phishing' else 0
        scan.status = 'completed'
        scan.completed_at = timezone.now()
        scan.save()

        result = {
            'risk': detection['risk'],
            'matched_keywords': detection['matched_keywords'],
            'flagged_sender': detection['flagged_sender'],
            'subject': subject,
            'sender': sender,
        }

    return render(request, 'scanner/scan.html', {'form': form, 'result': result})


@login_required
def history_view(request):
    scans = EmailScan.objects.filter(user=request.user).prefetch_related('emails')
    return render(request, 'scanner/history.html', {'scans': scans})



@login_required
def community_list(request):
    approved = FlaggedSender.objects.filter(is_active=True).order_by('-created_at')
    pending = CommunityFlag.objects.filter(status='pending')
    return render(request, 'community/list.html', {
        'approved': approved,
        'pending': pending,
    })


@login_required
def community_flag(request):
    form = CommunityFlagForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        CommunityFlag.objects.create(
            submitted_by=request.user,
            value=form.cleaned_data['value'].lower().strip(),
            type=form.cleaned_data['type'],
            reason=form.cleaned_data['reason'],
            evidence_url=form.cleaned_data.get('evidence_url', ''),
        )
        return render(request, 'community/flag.html', {'form': CommunityFlagForm(), 'submitted': True})
    return render(request, 'community/flag.html', {'form': form})


@login_required
def community_my_flags(request):
    flags = CommunityFlag.objects.filter(submitted_by=request.user)
    return render(request, 'community/my_flags.html', {'flags': flags})