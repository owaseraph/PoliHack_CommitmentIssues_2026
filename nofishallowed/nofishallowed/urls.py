from django.contrib import admin
from django.contrib.auth.decorators import login_required
from django.db.models import Sum
from django.shortcuts import render
from django.urls import include, path


def landing(request):
    return render(request, 'landing.html')


def downloads(request):
    return render(request, 'downloads.html')


@login_required
def dashboard(request):
    from scanner.models import EmailScan
    scans = EmailScan.objects.filter(user=request.user)
    context = {
        'total_scans': scans.count(),
        'total_scanned': scans.aggregate(t=Sum('emails_scanned'))['t'] or 0,
        'total_phishing': scans.aggregate(t=Sum('phishing_detected'))['t'] or 0,
    }
    return render(request, 'dashboard.html', context)


urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('accounts.urls')),
    path('scanner/', include('scanner.urls')),
    path('dashboard/', dashboard, name='dashboard'),
    path('downloads/', downloads, name='downloads'),
    path('', landing, name='landing'),
]