import logging
from datetime import timedelta
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from jobApp.models import Job, JobAlert
from jobApp.utils import send_templated_email

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Sends personalized job alerts to users based on their preferences.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--frequency',
            type=str,
            help='Specify frequency to send alerts for (Daily, Weekly, Bi-Weekly, Monthly). If not specified, all frequencies will be triggered.',
            choices=['Daily', 'Weekly', 'Bi-Weekly', 'Monthly'],
            nargs='?'
        )

    def handle(self, *args, **options):
        frequency_filter = options.get('frequency')
        frequencies_to_process = [frequency_filter] if frequency_filter else [
            choice[0] for choice in JobAlert.FREQUENCY_CHOICES
        ]

        now = timezone.now()
        logger.info(f"Processing job alerts for: {frequencies_to_process}")

        lookbacks = {
            'Daily': timedelta(days=1),
            'Weekly': timedelta(weeks=1),
            'Bi-Weekly': timedelta(weeks=2),
            'Monthly': timedelta(days=30),
        }

        for frequency in frequencies_to_process:
            logger.info(f"--- Starting {frequency} alerts ---")

            default_look_back = lookbacks.get(frequency, timedelta(days=1))
            earliest_date = now - default_look_back

            base_jobs = Job.objects.filter(
                is_active=True,
                date_posted__gte=earliest_date
            ).filter(
                Q(job_expiry_date__isnull=True) | Q(job_expiry_date__gte=now)
            )

            alerts = JobAlert.objects.filter(
                is_active=True,
                frequency=frequency
            ).select_related('user').prefetch_related('categories')

            for alert in alerts:
                try:
                    job_filter_start_time = alert.last_sent or earliest_date
                    matching_jobs = base_jobs.filter(date_posted__gte=job_filter_start_time)

                    # Apply filters (keywords, categories, locations, job_types)
                    if alert.keywords:
                        keyword_queries = Q()
                        for keyword in [k.strip() for k in alert.keywords.split(',') if k.strip()]:
                            keyword_queries |= Q(title__icontains=keyword)
                            keyword_queries |= Q(description__icontains=keyword)
                            keyword_queries |= Q(company_name__icontains=keyword)
                        matching_jobs = matching_jobs.filter(keyword_queries)

                    if alert.categories.exists():
                        matching_jobs = matching_jobs.filter(category__in=alert.categories.all())

                    if alert.locations:
                        location_queries = Q()
                        for loc in [l.strip() for l in alert.locations.split(',') if l.strip()]:
                            location_queries |= Q(location__icontains=loc)
                        matching_jobs = matching_jobs.filter(location_queries)

                    if alert.job_types:
                        job_type_queries = Q()
                        for jt in [j.strip() for j in alert.job_types.split(',') if j.strip()]:
                            job_type_queries |= Q(job_type__iexact=jt)
                        matching_jobs = matching_jobs.filter(job_type_queries)

                    matching_jobs = matching_jobs.distinct()

                    if matching_jobs.exists():
                        logger.info(
                            f"Alert '{alert.alert_name}' for {alert.user.email}: {matching_jobs.count()} jobs"
                        )

                        context = {
                            'user': alert.user,
                            'alert_name': alert.alert_name,
                            'new_jobs': matching_jobs,
                            'portal_name': getattr(settings, 'PORTAL_NAME', 'JobPortal'),
                            'unsubscribe_link': f"{settings.BASE_URL}/applicant/job-alerts/",
                        }

                        sent = send_templated_email(
                            template_name="emails/job_alert_email.html",
                            subject=f"Your Job Alert: New {alert.alert_name} Jobs!",
                            recipient_list=[alert.user.email],
                            context=context
                        )

                        if sent:
                            logger.info(f"Sent job alert to {alert.user.email}")
                        else:
                            logger.error(f"Failed to send job alert to {alert.user.email}")

                    # Always update last_sent
                    alert.last_sent = now
                    alert.save(update_fields=['last_sent'])

                except Exception as e:
                    logger.error(
                        f"Error processing alert {alert.id} ({alert.alert_name}) "
                        f"for {alert.user.email}: {e}", exc_info=True
                    )
                    continue

            logger.info(f"--- Finished {frequency} alerts ---")

        logger.info("Job alert processing completed.")
