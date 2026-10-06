from django.urls import path, include
from rest_framework.routers import DefaultRouter
from aggregator import views

# DRF Router setup
router = DefaultRouter()
router.register(r'feeds', views.FeedViewSet, basename='api-feed')
router.register(r'iocs', views.IOCViewSet, basename='api-ioc')
router.register(r'correlation', views.CorrelationResultViewSet, basename='api-correlation')

urlpatterns = [
    # Authentication routes
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),

    # HTML Views
    path('', views.dashboard_view, name='dashboard'),
    path('feeds/', views.feed_management_view, name='feed_management'),
    path('feeds/<int:feed_id>/process/', views.process_feed_trigger, name='process_feed'),
    path('feeds/<int:feed_id>/toggle/', views.toggle_feed, name='toggle_feed'),
    path('feeds/<int:feed_id>/delete/', views.delete_feed, name='delete_feed'),
    path('iocs/', views.ioc_explorer_view, name='ioc_explorer'),
    path('iocs/<int:ioc_id>/detail/', views.ioc_detail_modal, name='ioc_detail_modal'),
    path('correlation/', views.correlation_view, name='correlation'),
    path('blocklists/', views.blocklists_view, name='blocklists'),
    path('reports/', views.reports_view, name='reports'),
    path('logs/', views.activity_logs_view, name='activity_logs'),

    # REST APIs
    path('api/', include(router.urls)),
    path('api/correlation/run/', views.CorrelationRunAPI.as_view(), name='api-correlation-run'),
    path('api/blocklists/generate/', views.BlocklistGenerateAPI.as_view(), name='api-blocklist-generate'),
    path('api/reports/', views.ReportsAPI.as_view(), name='api-reports-summary'),
    path('api/dashboard/stats/', views.DashboardStatsAPI.as_view(), name='api-dashboard-stats'),
]
