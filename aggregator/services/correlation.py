from django.utils import timezone
from aggregator.models import IOC, IOCSource, CorrelationResult, ActivityLog
from aggregator.services.risk_engine import calculate_risk_and_severity

def run_correlation_engine(user=None):
    """
    Correlates all stored IOCs by identifying feed overlaps, calculating risk scores,
    updating the IOC database records, and logging the actions.
    """
    iocs = IOC.objects.filter(status='Active')
    correlated_count = 0
    total_iocs = iocs.count()
    
    for ioc in iocs:
        sources = IOCSource.objects.filter(ioc=ioc)
        source_count = sources.count()
        
        # Calculate sum of occurrences across sources
        occurrence_count = sum(s.occurrence_count for s in sources)
        
        # Get categories of all source feeds
        categories = [s.feed.category for s in sources]
        
        # Calculate scores
        risk_score, severity, reason = calculate_risk_and_severity(
            source_count=source_count,
            occurrence_count=occurrence_count,
            ioc_type=ioc.ioc_type,
            categories=categories,
            last_seen=ioc.last_seen
        )
        
        # Update IOC record
        ioc.risk_score = risk_score
        ioc.severity = severity
        ioc.save()
        
        # Create or update CorrelationResult
        corr_result, created = CorrelationResult.objects.get_or_create(ioc=ioc)
        corr_result.source_count = source_count
        corr_result.occurrence_count = occurrence_count
        corr_result.risk_score = risk_score
        corr_result.severity = severity
        corr_result.reason = reason
        corr_result.correlated_at = timezone.now()
        corr_result.save()
        
        if source_count > 1:
            correlated_count += 1
            
    # Write activity log
    ActivityLog.objects.create(
        user=user,
        action="Run Correlation Engine",
        module="correlation",
        status="Success",
        description=f"Correlated {total_iocs} active IOCs. Identified {correlated_count} cross-feed overlaps."
    )
    
    return {
        'total_iocs': total_iocs,
        'correlated_count': correlated_count
    }
