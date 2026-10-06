import csv
import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.utils import timezone
from django.http import HttpResponse, JsonResponse
from django.core.paginator import Paginator
from django.db.models import Q, Sum
from django.views.decorators.http import require_POST

# DRF Imports
from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

# App Imports
from aggregator.models import Feed, IOC, IOCSource, CorrelationResult, Blocklist, ActivityLog
from aggregator.forms import RegistrationForm, FeedForm
from aggregator.serializers import (
    FeedSerializer, IOCSerializer, CorrelationResultSerializer, 
    BlocklistSerializer, ActivityLogSerializer
)

# Services
from aggregator.services.feed_fetcher import fetch_remote_feed
from aggregator.services.feed_parser import parse_feed_content
from aggregator.services.correlation import run_correlation_engine
from aggregator.services.blocklist import generate_blocklist_file
from aggregator.services.reporting import get_report_statistics, compile_threat_report_file


# ==========================================
# AUTHENTICATION VIEWS
# ==========================================

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
        
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            ActivityLog.objects.create(
                user=user,
                action="User Login",
                module="auth",
                status="Success",
                description=f"User '{username}' logged in successfully."
            )
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid username or password.")
            ActivityLog.objects.create(
                user=None,
                action="User Login",
                module="auth",
                status="Error",
                description=f"Failed login attempt for username '{username}'."
            )
            
    return render(request, 'aggregator/login.html')

def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
        
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            
            ActivityLog.objects.create(
                user=user,
                action="User Registration",
                module="auth",
                status="Success",
                description=f"New user accounts registered: '{user.username}'."
            )
            
            # Auto log in user
            login(request, user)
            return redirect('dashboard')
        else:
            for error in form.errors.values():
                messages.error(request, error)
    else:
        form = RegistrationForm()
        
    return render(request, 'aggregator/register.html', {'form': form})

@login_required
def logout_view(request):
    username = request.user.username
    ActivityLog.objects.create(
        user=request.user,
        action="User Logout",
        module="auth",
        status="Success",
        description=f"User '{username}' logged out."
    )
    logout(request)
    return redirect('login')


# ==========================================
# CORE HTML VIEWS
# ==========================================

@login_required
def dashboard_view(request):
    # Total Active Stats
    stats = get_report_statistics()
    
    # Recent Threats table (Top 10 most recently updated active IOCs)
    recent_iocs = IOC.objects.filter(status='Active').order_by('-updated_at')[:10]
    
    # Retrieve recent activities for dashboard audit logs panel
    recent_logs = ActivityLog.objects.order_by('-timestamp')[:5]
    
    context = {
        'stats': stats,
        'recent_iocs': recent_iocs,
        'recent_logs': recent_logs,
        'page': 'dashboard'
    }
    return render(request, 'aggregator/dashboard.html', context)

# imports...

def decode_uploaded_file(uploaded_file):
    """
    Decode uploaded IOC feed file.
    """
    data = uploaded_file.read()

    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


@login_required
def feed_management_view(request):
    feeds = Feed.objects.all().order_by('-created_at')

    if request.method == 'POST':
        form = FeedForm(request.POST, request.FILES)

        if form.is_valid():
            feed = form.save(commit=False)

            # Handle source logic
            if feed.source == 'File Upload' and 'file_upload' in request.FILES:
                uploaded_file = request.FILES['file_upload']

                try:
                    content = decode_uploaded_file(uploaded_file)
                    feed.raw_content = content
                    feed.save()

                    successful, rejected = parse_feed_content(
                        content,
                        feed.feed_type
                    )

                    process_parsed_iocs(
                        feed,
                        successful,
                        rejected,
                        request.user
                    )

                    messages.success(
                        request,
                        f"Feed '{feed.name}' created and processed: "
                        f"{len(successful)} IOCs imported, "
                        f"{len(rejected)} rejected."
                    )

                except Exception as exc:
                    messages.error(
                        request,
                        f"Error parsing uploaded file: {exc}"
                    )

                    return redirect('feed_management')

            else:
                feed.save()

                messages.success(
                    request,
                    f"Feed '{feed.name}' created successfully. "
                    f"Click Process to retrieve data."
                )

            return redirect('feed_management')

        else:
            for error in form.errors.values():
                messages.error(request, error)

    else:
        form = FeedForm()

    context = {
        'feeds': feeds,
        'form': form,
        'page': 'feed_management',
    }

    return render(
        request,
        'aggregator/feed_management.html',
        context
    )

@login_required
@require_POST
def process_feed_trigger(request, feed_id):
    """
    HTTP POST view to manually trigger parsing of a feed.
    For remote feeds, fetches HTTP url. For file uploads, requires a re-upload or uses previous.
    """
    feed = get_object_or_404(Feed, id=feed_id)
    if not feed.is_active:
        messages.error(request, f"Feed '{feed.name}' is currently disabled.")
        return redirect('feed_management')
        
    content = ""
    try:
        if feed.source == 'URL':
            content = fetch_remote_feed(feed.url)
        elif feed.source == 'File Upload':
            content = feed.raw_content
            
            if not content:
                messages.error(
                    request,
                    "No stored content is available for this file feed."
                    )
                return redirect('feed_management')
            
        successful, rejected = parse_feed_content(content, feed.feed_type)
        process_parsed_iocs(feed, successful, rejected, request.user)
        
        messages.success(request, f"Successfully processed feed '{feed.name}': {len(successful)} indicators imported, {len(rejected)} rejected.")
    except Exception as e:
        messages.error(request, f"Error processing feed '{feed.name}': {str(e)}")
        ActivityLog.objects.create(
            user=request.user,
            action="Process Feed",
            module="feed",
            status="Error",
            description=f"Error processing feed '{feed.name}': {str(e)}"
        )
        
    return redirect('feed_management')

@login_required
@require_POST
def toggle_feed(request, feed_id):
    feed = get_object_or_404(Feed, id=feed_id)

    feed.is_active = not feed.is_active
    feed.save(update_fields=['is_active', 'updated_at'])

    status_str = "enabled" if feed.is_active else "disabled"

    ActivityLog.objects.create(
        user=request.user,
        action="Toggle Feed",
        module="feed",
        status="Success",
        description=f"Feed '{feed.name}' was {status_str}."
    )

    messages.success(
        request,
        f"Feed '{feed.name}' is now {status_str}."
    )

    return redirect('feed_management')

@login_required
@require_POST
def delete_feed(request, feed_id):
    feed = get_object_or_404(Feed, id=feed_id)

    name = feed.name

    feed.delete()

    ActivityLog.objects.create(
        user=request.user,
        action="Delete Feed",
        module="feed",
        status="Success",
        description=f"Feed '{name}' deleted from database."
    )

    messages.success(
        request,
        f"Feed '{name}' deleted successfully."
    )

    return redirect('feed_management')


@login_required
def ioc_explorer_view(request):
    query = request.GET.get('q', '').strip()
    ioc_type = request.GET.get('type', '')
    severity = request.GET.get('severity', '')
    min_risk = request.GET.get('min_risk', '')
    
    iocs = IOC.objects.filter(status='Active')
    
    if query:
        iocs = iocs.filter(Q(value__icontains=query) | Q(normalized_value__icontains=query))
    if ioc_type:
        iocs = iocs.filter(ioc_type=ioc_type)
    if severity:
        iocs = iocs.filter(severity=severity)
    if min_risk:
        try:
            iocs = iocs.filter(risk_score__gte=int(min_risk))
        except ValueError:
            pass
            
    # Sort
    iocs = iocs.order_by('-risk_score', '-updated_at')
    
    # Pagination
    paginator = Paginator(iocs, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'query': query,
        'ioc_type': ioc_type,
        'severity': severity,
        'min_risk': min_risk,
        'page': 'ioc_explorer'
    }
    return render(request, 'aggregator/ioc_explorer.html', context)

@login_required
def ioc_detail_modal(request, ioc_id):
    ioc = get_object_or_404(IOC, id=ioc_id)

    sources = ioc.sources.select_related('feed').all()

    try:
        correlation = ioc.correlation_result
    except CorrelationResult.DoesNotExist:
        correlation = None

    sources_data = []

    for s in sources:
        sources_data.append({
            'feed_name': s.feed.name,
            'category': s.feed.category,
            'occurrence_count': s.occurrence_count,
            'first_seen': timezone.localtime(s.first_seen).strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen': timezone.localtime(s.last_seen).strftime('%Y-%m-%d %H:%M:%S')
        })

    data = {
        'id': ioc.id,
        'value': ioc.value,
        'normalized_value': ioc.normalized_value,
        'ioc_type': ioc.ioc_type,
        'first_seen': timezone.localtime(ioc.first_seen).strftime('%Y-%m-%d %H:%M:%S'),
        'last_seen': timezone.localtime(ioc.last_seen).strftime('%Y-%m-%d %H:%M:%S'),
        'severity': ioc.severity,
        'risk_score': ioc.risk_score,
        'status': ioc.status,
        'sources': sources_data,
        'reason': correlation.reason if correlation else "No correlation calculated yet."
    }

    return JsonResponse(data)

@login_required
def correlation_view(request):
    correlations = CorrelationResult.objects.select_related('ioc').order_by('-risk_score', '-source_count')[:50]
    
    if request.method == 'POST':
        # Trigger correlation engine
        stats = run_correlation_engine(user=request.user)
        messages.success(request, f"Correlation run complete. Evaluated {stats['total_iocs']} indicators, identified {stats['correlated_count']} overlaps.")
        return redirect('correlation')
        
    context = {
        'correlations': correlations,
        'page': 'correlation'
    }
    return render(request, 'aggregator/correlation.html', context)

@login_required
def blocklists_view(request):
    history = Blocklist.objects.all().order_by('-generated_at')

    if request.method == 'POST':
        ioc_type = request.POST.get('ioc_type', 'IP')
        min_severity = request.POST.get('min_severity', 'Low')

        try:
            min_risk_score = int(
                request.POST.get('min_risk_score', 0)
            )
        except (TypeError, ValueError):
            messages.error(
                request,
                "Minimum risk score must be a number."
            )
            return redirect('blocklists')

        if not 0 <= min_risk_score <= 100:
            messages.error(
                request,
                "Risk score must be between 0 and 100."
            )
            return redirect('blocklists')

        file_format = request.POST.get(
            'file_format',
            'TXT'
        ).upper()

        try:
            content, filename, indicator_count = (
                generate_blocklist_file(
                    ioc_type=ioc_type,
                    min_severity=min_severity,
                    min_risk_score=min_risk_score,
                    file_format=file_format,
                    user=request.user
                )
            )

            if file_format == 'CSV':
                content_type = 'text/csv'
            elif file_format == 'JSON':
                content_type = 'application/json'
            else:
                content_type = 'text/plain'

            response = HttpResponse(
                content,
                content_type=content_type
            )

            response[
                'Content-Disposition'
            ] = f'attachment; filename="{filename}"'

            return response

        except Exception as exc:
            ActivityLog.objects.create(
                user=request.user,
                action="Generate Blocklist",
                module="blocklist",
                status="Error",
                description=str(exc)
            )

            messages.error(
                request,
                f"Unable to generate blocklist: {exc}"
            )

            return redirect('blocklists')

    context = {
        'history': history,
        'page': 'blocklists'
    }

    return render(
        request,
        'aggregator/blocklists.html',
        context
    )



@login_required
def reports_view(request):
    stats = get_report_statistics()
    
    if request.method == 'POST':
        file_format = request.POST.get('file_format', 'JSON')
        content, filename = compile_threat_report_file(file_format, request.user)
        
        response = HttpResponse(content, content_type='text/plain')
        if file_format.upper() == 'CSV':
            response = HttpResponse(content, content_type='text/csv')
        elif file_format.upper() == 'JSON':
            response = HttpResponse(content, content_type='application/json')
            
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
        
    context = {
        'stats': stats,
        'page': 'reports'
    }
    return render(request, 'aggregator/reports.html', context)

@login_required
def activity_logs_view(request):
    logs = ActivityLog.objects.select_related('user').order_by('-timestamp')
    
    # Simple pagination
    paginator = Paginator(logs, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'page': 'activity_logs'
    }
    return render(request, 'aggregator/activity_logs.html', context)


# ==========================================
# BACKEND DB IMPORT PIPELINE HELPER
# ==========================================

def process_parsed_iocs(feed, successful_iocs, rejected_iocs, user):
    """
    Takes parsed outputs, inserts/updates the database IOC tables, 
    and handles warnings/rejections in activity logs.
    """
    imported_count = 0
    
    for item in successful_iocs:
        raw_val = item['raw_value']
        norm_val = item['normalized_value']
        ioc_type = item['type']
        
        # Get or create IOC
        ioc, created = IOC.objects.get_or_create(
            normalized_value=norm_val,
            defaults={
                'value': raw_val,
                'ioc_type': ioc_type,
                'severity': 'Low',
                'risk_score': 20,
                'status': 'Active'
            }
        )
        
        # Link source feed
        source_rel, src_created = IOCSource.objects.get_or_create(
            ioc=ioc,
            feed=feed,
            defaults={
                'occurrence_count': 1
            }
        )
        if not src_created:
            source_rel.occurrence_count += 1
            source_rel.last_seen = timezone.now()
            source_rel.save()
            
        # Keep track of timestamps
        ioc.last_seen = timezone.now()
        ioc.save()
        
        imported_count += 1
        
    # Log rejections
    for item in rejected_iocs:
        ActivityLog.objects.create(
            user=user,
            action="IOC Rejected",
            module="feed",
            status="Warning",
            description=f"Rejected '{item.get('raw_value', 'Unknown')}' from feed '{feed.name}'. Reason: {item.get('reason', 'N/A')}"
        )
        
    # Update Feed processed timestamp
    feed.last_processed_at = timezone.now()
    feed.save()
    
    # Log success activity
    ActivityLog.objects.create(
        user=user,
        action="Import Feed",
        module="feed",
        status="Success",
        description=f"Imported and parsed feed '{feed.name}'. Successfully loaded {imported_count} indicators. Rejected {len(rejected_iocs)} entries."
    )


# ==========================================
# DJANGO REST FRAMEWORK API VIEWSETS
# ==========================================

class FeedViewSet(viewsets.ModelViewSet):
    queryset = Feed.objects.all().order_by('-created_at')
    serializer_class = FeedSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        # Allow creating and immediate processing of remote URL feeds
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        feed = serializer.save()
        
        ActivityLog.objects.create(
            user=request.user,
            action="API Create Feed",
            module="feed",
            status="Success",
            description=f"Feed '{feed.name}' created via REST API."
        )
        
        # If remote URL is active, fetch and parse automatically
        if feed.source == 'URL' and feed.url and feed.is_active:
            try:
                content = fetch_remote_feed(feed.url)
                successful, rejected = parse_feed_content(content, feed.feed_type)
                process_parsed_iocs(feed, successful, rejected, request.user)
            except Exception as e:
                # Still return feed creation, but log the error
                ActivityLog.objects.create(
                    user=request.user,
                    action="API Process Feed",
                    module="feed",
                    status="Error",
                    description=f"Failed processing URL feed {feed.name} post API-creation: {str(e)}"
                )
        
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class IOCViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = IOC.objects.filter(status='Active').order_by('-risk_score')
    serializer_class = IOCSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = super().get_queryset()
        ioc_type = self.request.query_params.get('type')
        severity = self.request.query_params.get('severity')
        min_risk = self.request.query_params.get('min_risk')
        
        if ioc_type:
            queryset = queryset.filter(ioc_type=ioc_type)
        if severity:
            queryset = queryset.filter(severity=severity)
        if min_risk:
            try:
                queryset = queryset.filter(risk_score__gte=int(min_risk))
            except ValueError:
                pass
        return queryset


class CorrelationResultViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = CorrelationResult.objects.all().order_by('-risk_score', '-source_count')
    serializer_class = CorrelationResultSerializer
    permission_classes = [IsAuthenticated]


class CorrelationRunAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            stats = run_correlation_engine(user=request.user)
            return Response({
                'status': 'Success',
                'message': 'Correlation process executed successfully.',
                'total_iocs_evaluated': stats['total_iocs'],
                'overlaps_identified': stats['correlated_count']
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'status': 'Error',
                'message': f"Error during correlation cycle: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class BlocklistGenerateAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        ioc_type = request.data.get('ioc_type')
        min_severity = request.data.get('min_severity', 'Low')
        min_risk_score = request.data.get('min_risk_score', 0)
        file_format = request.data.get('file_format', 'TXT')
        
        if not ioc_type:
            return Response({'error': 'ioc_type is a required parameter'}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            min_risk_score = int(min_risk_score)
        except ValueError:
            return Response({'error': 'min_risk_score must be an integer'}, status=status.HTTP_400_BAD_REQUEST)
            
        content, filename, count = generate_blocklist_file(
            ioc_type=ioc_type,
            min_severity=min_severity,
            min_risk_score=min_risk_score,
            file_format=file_format,
            user=request.user
        )
        
        return Response({
            'status': 'Success',
            'filename': filename,
            'indicator_count': count,
            'file_content': content
        }, status=status.HTTP_200_OK)


class ReportsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        stats = get_report_statistics()
        return Response(stats, status=status.HTTP_200_OK)


class DashboardStatsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        stats = get_report_statistics()
        return Response({
            'total_feeds': stats['feeds']['total'],
            'active_feeds': stats['feeds']['active'],
            'total_indicators': stats['iocs']['total'],
            'unique_active_iocs': stats['iocs']['unique_active'],
            'correlated_iocs': stats['iocs']['correlated'],
            'severity_breakdown': stats['iocs']['by_severity'],
            'type_breakdown': stats['iocs']['by_type']
        }, status=status.HTTP_200_OK)
