# jobApp/management/commands/send_job_alerts.py
import logging
from datetime import timedelta

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.template.loader import render_to_string, TemplateDoesNotExist
from django.utils import timezone
from django.utils.html import strip_tags


from jobApp.models import Job, JobAlert

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Sends personalized job alerts to users based on their preferences.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--frequency',
            type=str,
            help='Specify frequency to send alerts for (Daily, Weekly, Bi-Weekly, Monthly). If not specified, all frequencies will be triggered.',
            choices=['Daily', 'Weekly', 'Bi-Weekly', 'Monthly'],
            nargs='?'  # Make it optional
        )

    def handle(self, *args, **options):
        frequency_filter = options.get('frequency')
        frequencies_to_process = [frequency_filter] if frequency_filter else [
            choice[0] for choice in JobAlert.FREQUENCY_CHOICES
        ]

        logger.info(f"Processing job alerts for: {frequencies_to_process}")

        now = timezone.now()

        for frequency in frequencies_to_process:
            logger.info(f"--- Starting {frequency} alerts ---")

            # Default look-back period
            lookbacks = {
                'Daily': timedelta(days=1),
                'Weekly': timedelta(weeks=1),
                'Bi-Weekly': timedelta(weeks=2),
                'Monthly': timedelta(days=30),
            }
            default_look_back = lookbacks.get(frequency, timedelta(days=1))

            # Pre-filter jobs for this frequency window
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

            logger.info(f"Found {alerts.count()} active {frequency} alerts")

            for alert in alerts:
                try:
                    job_filter_start_time = alert.last_sent or earliest_date
                    matching_jobs = base_jobs.filter(date_posted__gte=job_filter_start_time)

                    # Keywords
                    if alert.keywords:
                        keyword_queries = Q()
                        for keyword in [k.strip() for k in alert.keywords.split(',') if k.strip()]:
                            keyword_queries |= Q(title__icontains=keyword)
                            keyword_queries |= Q(description__icontains=keyword)
                            keyword_queries |= Q(company_name__icontains=keyword)
                        matching_jobs = matching_jobs.filter(keyword_queries)

                    # Categories
                    if alert.categories.exists():
                        matching_jobs = matching_jobs.filter(category__in=alert.categories.all())

                    # Locations
                    if alert.locations:
                        location_queries = Q()
                        for loc in [l.strip() for l in alert.locations.split(',') if l.strip()]:
                            location_queries |= Q(location__icontains=loc)
                        matching_jobs = matching_jobs.filter(location_queries)

                    # Job Types
                    if alert.job_types:
                        job_type_queries = Q()
                        for jt in [j.strip() for j in alert.job_types.split(',') if j.strip()]:
                            job_type_queries |= Q(job_type__iexact=jt)
                        matching_jobs = matching_jobs.filter(job_type_queries)

                    matching_jobs = matching_jobs.distinct()

                    if matching_jobs.exists():
                        logger.info(
                            f"Alert '{alert.alert_name}' ({alert.frequency}) "
                            f"for {alert.user.email} -> {matching_jobs.count()} jobs"
                        )

                        context = {
                            'user': alert.user,
                            'alert_name': alert.alert_name,
                            'new_jobs': matching_jobs,
                            'portal_name': getattr(settings, 'PORTAL_NAME', 'JobPortal'),
                            'unsubscribe_link': f"{settings.BASE_URL}/applicant/job-alerts/",
                        }

                        try:
                            html_message = render_to_string('emails/job_alert_email.html', context)
                        except TemplateDoesNotExist:
                            html_message = None
                            logger.warning("Email template not found, sending plain text only.")

                        plain_message = render_to_string('emails/job_alert_email.txt', context) \
                            if html_message is None else \
                            strip_tags(html_message)

                        email = EmailMultiAlternatives(
                            subject=f"Your Job Alert: New {alert.alert_name} Jobs!",
                            body=plain_message,
                            from_email=settings.DEFAULT_FROM_EMAIL,
                            to=[alert.user.email],
                        )
                        if html_message:
                            email.attach_alternative(html_message, "text/html")

                        email.send()
                        logger.info(f"Sent job alert to {alert.user.email}")

                    # Always update last_sent to avoid reprocessing
                    alert.last_sent = now
                    alert.save(update_fields=['last_sent'])
                    logger.debug(f"Updated last_sent for alert '{alert.alert_name}'")

                except Exception as e:
                    logger.error(
                        f"Error processing alert {alert.id} ({alert.alert_name}) "
                        f"for {alert.user.email}: {e}", exc_info=True
                    )
                    # Skip this alert but continue others

            logger.info(f"--- Finished {frequency} alerts ---")

        logger.info("Job alert processing completed.")
        logger.warning("Note: Emails are sent synchronously. Consider Celery for scale.")
