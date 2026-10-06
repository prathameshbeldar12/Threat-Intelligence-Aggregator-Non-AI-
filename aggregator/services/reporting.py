import csv
import json
from io import StringIO
from django.utils import timezone
from aggregator.models import Feed, IOC, CorrelationResult, Blocklist, ActivityLog

def get_report_statistics():
    """
    Aggregates statistical database metrics for executive summaries and tables.
    """
    total_feeds = Feed.objects.count()
    active_feeds = Feed.objects.filter(is_active=True).count()
    
    total_iocs = IOC.objects.count()
    unique_iocs = IOC.objects.filter(status='Active')
    unique_count = unique_iocs.count()
    
    # Severity distribution
    severity_stats = {
        'Critical': unique_iocs.filter(severity='Critical').count(),
        'High': unique_iocs.filter(severity='High').count(),
        'Medium': unique_iocs.filter(severity='Medium').count(),
        'Low': unique_iocs.filter(severity='Low').count(),
    }
    
    # IOC type distribution
    type_stats = {
        'IPv4': unique_iocs.filter(ioc_type='IPv4').count(),
        'Domain': unique_iocs.filter(ioc_type='Domain').count(),
        'URL': unique_iocs.filter(ioc_type='URL').count(),
        'Hash': unique_iocs.filter(ioc_type='Hash').count(),
        'Email': unique_iocs.filter(ioc_type='Email').count(),
    }
    
    # Correlation metrics
    correlations = CorrelationResult.objects.all()
    correlated_count = correlations.filter(source_count__gt=1).count()
    
    # Top 10 correlated/risky IOCs
    top_correlated_results = correlations.order_by('-risk_score', '-source_count')[:10]
    top_iocs = []
    for cr in top_correlated_results:
        top_iocs.append({
            'indicator': cr.ioc.normalized_value,
            'type': cr.ioc.ioc_type,
            'sources': cr.source_count,
            'occurrences': cr.occurrence_count,
            'risk_score': cr.risk_score,
            'severity': cr.severity
        })
        
    # Blocklist summaries
    blocklists = Blocklist.objects.all()
    blocklist_summary = {
        'IP': blocklists.filter(blocklist_type__in=['IP', 'IPv4']).count(),
        'Domain': blocklists.filter(blocklist_type='Domain').count(),
        'URL': blocklists.filter(blocklist_type='URL').count(),
        'Hash': blocklists.filter(blocklist_type='Hash').count(),
        'total_generated': blocklists.count()
    }
    
    return {
        'timestamp': timezone.localtime(
            timezone.now()
            ).strftime('%Y-%m-%dT%H:%M:%S%z'),
        'system_name': "Threat Intelligence Aggregator",
        'feeds': {
            'total': total_feeds,
            'active': active_feeds
        },
        'iocs': {
            'total': total_iocs,
            'unique_active': unique_count,
            'correlated': correlated_count,
            'critical': severity_stats['Critical'],
            'high': severity_stats['High'],
            'by_type': type_stats,
            'by_severity': severity_stats
        },
        'top_threats': top_iocs,
        'blocklists': blocklist_summary
    }

def compile_threat_report_file(file_format='JSON', user=None):
    """
    Compiles threat intelligence reports to JSON or CSV download format.
    """
    stats = get_report_statistics()
    content = ""
    filename = f"threat_report_{timezone.now().strftime('%Y%m%d%H%M%S')}"
    
    if file_format.upper() == 'JSON':
        content = json.dumps(stats, indent=2)
        filename += ".json"
        
    elif file_format.upper() == 'CSV':
        f = StringIO()
        writer = csv.writer(f)
        
        # Write Title
        writer.writerow(['THREAT INTELLIGENCE SUMMARY REPORT'])
        writer.writerow(['Generated At', stats['timestamp']])
        writer.writerow(['System Name', stats['system_name']])
        writer.writerow([])
        
        # Write Executive Metrics
        writer.writerow(['METRIC', 'VALUE'])
        writer.writerow(['Total Feeds Processed', stats['feeds']['total']])
        writer.writerow(['Active Feeds', stats['feeds']['active']])
        writer.writerow(['Unique Active IOCs', stats['iocs']['unique_active']])
        writer.writerow(['Correlated IOCs', stats['iocs']['correlated']])
        writer.writerow(['Critical Severity IOCs', stats['iocs']['critical']])
        writer.writerow(['High Severity IOCs', stats['iocs']['high']])
        writer.writerow([])
        
        # Write Distribution by Type
        writer.writerow(['IOC TYPE', 'COUNT'])
        for ioc_type, count in stats['iocs']['by_type'].items():
            writer.writerow([ioc_type, count])
        writer.writerow([])
        
        # Write Distribution by Severity
        writer.writerow(['SEVERITY LEVEL', 'COUNT'])
        for sev, count in stats['iocs']['by_severity'].items():
            writer.writerow([sev, count])
        writer.writerow([])
        
        # Write Top Threats
        writer.writerow(['TOP CORRELATED IOCS'])
        writer.writerow(['Indicator', 'Type', 'Sources', 'Occurrences', 'Risk Score', 'Severity'])
        for threat in stats['top_threats']:
            writer.writerow([
                threat['indicator'],
                threat['type'],
                threat['sources'],
                threat['occurrences'],
                threat['risk_score'],
                threat['severity']
            ])
        content = f.getvalue()
        filename += ".csv"
        
    # Log report generation
    ActivityLog.objects.create(
        user=user,
        action="Compile Report",
        module="reporting",
        status="Success",
        description=f"Compiled executive threat report in {file_format} format."
    )
    
    return content, filename
