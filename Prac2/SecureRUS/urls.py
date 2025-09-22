"""
URL configuration for SecureRUS project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from django.contrib.auth.views import LogoutView
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.http import HttpResponse
from two_factor.views import LoginView, SetupView, BackupTokensView, QRGeneratorView, SetupCompleteView, ProfileView, DisableView

def simple_logout(request):
    logout(request)
    return redirect('/account/login/')

two_factor_urls = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', simple_logout, name='logout'),
    path('setup/', SetupView.as_view(), name='setup'),
    path('qrcode/', QRGeneratorView.as_view(), name='qr'),
    path('setup/complete/', SetupCompleteView.as_view(), name='setup_complete'),
    path('backup/tokens/', BackupTokensView.as_view(), name='backup_tokens'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('disable/', DisableView.as_view(), name='disable'),
]

urlpatterns = [
    path('', include("file_storage.urls")),
    path('manage/', admin.site.urls),
    path('account/', include((two_factor_urls, 'two_factor'), namespace='two_factor')),
]
