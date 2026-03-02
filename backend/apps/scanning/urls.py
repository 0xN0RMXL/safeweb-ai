from django.urls import path
from . import views

urlpatterns = [
    path('website/', views.WebsiteScanCreateView.as_view(), name='scan-website'),
    path('file/', views.FileScanCreateView.as_view(), name='scan-file'),
    path('url/', views.URLScanCreateView.as_view(), name='scan-url'),
    path('<uuid:id>/', views.ScanDetailView.as_view(), name='scan-detail'),
    path('<uuid:id>/delete/', views.ScanDeleteView.as_view(), name='scan-delete'),
    path('<uuid:id>/rescan/', views.RescanView.as_view(), name='scan-rescan'),
    path('<uuid:id>/export/', views.ScanExportView.as_view(), name='scan-export'),
]
