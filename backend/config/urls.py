from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('apps.accounts.urls')),
    path('api/contact/', include('apps.accounts.contact_urls')),
    path('api/careers/', include('apps.accounts.careers_urls')),
    path('api/user/', include('apps.accounts.profile_urls')),
    path('api/scan/', include('apps.scanning.urls')),
    path('api/scans/', include('apps.scanning.list_urls')),
    path('api/dashboard/', include('apps.scanning.dashboard_urls')),
    path('api/chat/', include('apps.chatbot.urls')),
    path('api/admin/', include('apps.admin_panel.urls')),
    path('api/learn/', include('apps.learn.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
