from django.contrib import admin
from aggregator.models import Feed, IOC, IOCSource, CorrelationResult, Blocklist, ActivityLog

@admin.register(Feed)
class FeedAdmin(admin.ModelAdmin):
    list_display = ('name', 'source', 'feed_type', 'category', 'is_active', 'last_processed_at')
    list_filter = ('source', 'feed_type', 'is_active')
    search_fields = ('name', 'category', 'url')

@admin.register(IOC)
class IOCAdmin(admin.ModelAdmin):
    list_display = ('normalized_value', 'ioc_type', 'severity', 'risk_score', 'status', 'last_seen')
    list_filter = ('ioc_type', 'severity', 'status')
    search_fields = ('value', 'normalized_value')

@admin.register(IOCSource)
class IOCSourceAdmin(admin.ModelAdmin):
    list_display = ('ioc', 'feed', 'occurrence_count', 'last_seen')
    list_filter = ('feed',)
    search_fields = ('ioc__normalized_value', 'feed__name')

@admin.register(CorrelationResult)
class CorrelationResultAdmin(admin.ModelAdmin):
    list_display = ('ioc', 'source_count', 'occurrence_count', 'risk_score', 'severity', 'correlated_at')
    list_filter = ('severity',)
    search_fields = ('ioc__normalized_value', 'reason')

@admin.register(Blocklist)
class BlocklistAdmin(admin.ModelAdmin):
    list_display = ('name', 'blocklist_type', 'severity_filter', 'indicator_count', 'file_format', 'generated_at')
    list_filter = ('blocklist_type', 'file_format')
    search_fields = ('name',)

@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'user', 'action', 'module', 'status', 'description')
    list_filter = ('module', 'status')
    search_fields = ('action', 'description', 'user__username')
