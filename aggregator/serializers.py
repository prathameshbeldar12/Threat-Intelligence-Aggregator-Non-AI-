from rest_framework import serializers
from aggregator.models import Feed, IOC, IOCSource, CorrelationResult, Blocklist, ActivityLog
from django.contrib.auth.models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']


class FeedSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feed
        fields = '__all__'


class IOCSourceSerializer(serializers.ModelSerializer):
    feed_name = serializers.CharField(source='feed.name', read_only=True)
    feed_category = serializers.CharField(source='feed.category', read_only=True)

    class Meta:
        model = IOCSource
        fields = ['id', 'feed', 'feed_name', 'feed_category', 'first_seen', 'last_seen', 'occurrence_count']


class IOCSerializer(serializers.ModelSerializer):
    sources = IOCSourceSerializer(many=True, read_only=True)

    class Meta:
        model = IOC
        fields = '__all__'


class CorrelationResultSerializer(serializers.ModelSerializer):
    ioc_value = serializers.CharField(source='ioc.normalized_value', read_only=True)
    ioc_type = serializers.CharField(source='ioc.ioc_type', read_only=True)

    class Meta:
        model = CorrelationResult
        fields = '__all__'


class BlocklistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blocklist
        fields = '__all__'


class ActivityLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True, default='System')

    class Meta:
        model = ActivityLog
        fields = '__all__'
