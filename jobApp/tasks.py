from celery import shared_task
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.db.models import Q

from jobApp.models import Job, JobAlert
from jobApp.utils import send_templated_email

import logging
logger = logging.getLogger(__name__)


LOOKBACKS = {
    'Daily': timedelta(days=1),
    'Weekly': timedelta(weeks=1),
    'Bi-Weekly': timedelta(weeks=2),
    'Monthly': timedelta(days=30),
}


@shared_task(name="jobApp.process_job_alerts")
def process_job_alerts():
    """
    Background Celery task that processes ALL job alerts.
    Runs according to Celery Beat scheduling.
    """
    now = timezone.now()
    logger.info("Starting job alert processing...")

    for frequency, lookback in LOOKBACKS.items():
        logger.info(f"--- Processing {frequency} alerts ---")

        base_jobs = Job.objects.filter(
            is_active=True,
            date_posted__gte=now - lookback
        ).filter(
            Q(job_expiry_date__isnull=True) | Q(job_expiry_date__gte=now)
        )

        alerts = JobAlert.objects.filter(
            is_active=True,
            frequency=frequency
        ).select_related("user").prefetch_related("categories")

        for alert in alerts:
            try:
                job_filter_start = alert.last_sent or (now - lookback)
                matching_jobs = base_jobs.filter(date_posted__gte=job_filter_start)

                # Filter keywords
                if alert.keywords:
                    keyword_queries = Q()
                    for k in [x.strip() for x in alert.keywords.split(",") if x.strip()]:
                        keyword_queries |= (
                            Q(title__icontains=k) |
                            Q(description__icontains=k) |
                            Q(company_name__icontains=k)
                        )
                    matching_jobs = matching_jobs.filter(keyword_queries)

                # Filter categories
                if alert.categories.exists():
                    matching_jobs = matching_jobs.filter(category__in=alert.categories.all())

                # Filter locations
                if alert.locations:
                    loc_queries = Q()
                    for l in [x.strip() for x in alert.locations.split(",") if x.strip()]:
                        loc_queries |= Q(location__icontains=l)
                    matching_jobs = matching_jobs.filter(loc_queries)

                # Filter job types
                if alert.job_types:
                    jt_queries = Q()
                    for j in [x.strip() for x in alert.job_types.split(",") if x.strip()]:
                        jt_queries |= Q(job_type__iexact=j)
                    matching_jobs = matching_jobs.filter(jt_queries)

                matching_jobs = matching_jobs.distinct()

                if matching_jobs.exists():
                    logger.info(f"Sending {matching_jobs.count()} jobs to {alert.user.email}")

                    context = {
                        "user": alert.user,
                        "alert_name": alert.alert_name,
                        "new_jobs": matching_jobs,
                        "portal_name": getattr(settings, 'PORTAL_NAME', "JobPortal"),
                        "unsubscribe_link": f"{settings.BASE_URL}/applicant/job-alerts/",
                    }

                    send_templated_email(
                        template_name="emails/job_alert_email.html",
                        subject=f"New Job Matches for {alert.alert_name}",
                        recipient_list=[alert.user.email],
                        context=context
                    )

                # Always update last_sent
                alert.last_sent = now
                alert.save(update_fields=["last_sent"])

            except Exception as e:
                logger.error(f"Error processing alert {alert.id} ({alert.alert_name}): {e}", exc_info=True)

    logger.info("Job alert processing complete.")
