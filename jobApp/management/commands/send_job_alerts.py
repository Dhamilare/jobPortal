from django.core.management.base import BaseCommand, CommandError
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from datetime import timedelta
from django.db.models import Q
from jobApp.models import *

class Command(BaseCommand):
    help = 'Sends personalized job alerts to users based on their preferences.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--frequency',
            type=str,
            help='Specify frequency to send alerts for (Daily, Weekly, Bi-Weekly, Monthly). If not specified, all frequencies will be triggered.',
            choices=['Daily', 'Weekly', 'Bi-Weekly', 'Monthly'],
            nargs='?' # Make it optional
        )

    def handle(self, *args, **options):
        frequency_filter = options['frequency']
        frequencies_to_process = []

        if frequency_filter:
            frequencies_to_process.append(frequency_filter)
            self.stdout.write(self.style.SUCCESS(f'Processing {frequency_filter} job alerts...'))
        else:
            # If no frequency is specified, process all defined frequencies
            frequencies_to_process = [choice[0] for choice in JobAlert.FREQUENCY_CHOICES]
            self.stdout.write(self.style.SUCCESS('Processing all job alert frequencies...'))

        for frequency in frequencies_to_process:
            self.stdout.write(self.style.HTTP_INFO(f'--- Starting processing for {frequency} alerts ---'))
            try:
                # Get active job alerts for the specified frequency
                alerts = JobAlert.objects.filter(
                    is_active=True,
                    frequency=frequency
                ).select_related('user').prefetch_related('categories')

                # Determine the time range for new jobs based on frequency
                now = timezone.now()
                # For a new alert, last_sent is set to timezone.now() by the view.
                # This ensures that when an alert is first created, it only picks up
                # jobs posted *after* its creation, preventing a flood of old job notifications.
                # For subsequent runs, it uses the 'last_sent' timestamp of the alert.
                # If last_sent is None (e.g., for alerts created before this feature),
                # it will default to looking back by the frequency duration.
                
                # Default look-back period if last_sent is not set for an alert
                default_look_back = timedelta(days=1) # Default for daily
                if frequency == 'Weekly':
                    default_look_back = timedelta(weeks=1)
                elif frequency == 'Bi-Weekly':
                    default_look_back = timedelta(weeks=2)
                elif frequency == 'Monthly':
                    default_look_back = timedelta(days=30) # Approximate month

                self.stdout.write(self.style.MIGRATE_HEADING(f"Checking for {frequency} job alerts for {alerts.count()} active alerts..."))

                for alert in alerts:
                    # The actual start time for filtering jobs for *this specific alert*
                    # Use alert.last_sent if it exists, otherwise use the default look-back based on frequency
                    job_filter_start_time = alert.last_sent if alert.last_sent else (now - default_look_back)

                    matching_jobs = Job.objects.filter(
                        is_active=True,
                        date_posted__gte=job_filter_start_time # Jobs posted since the last alert for this frequency OR the default look-back
                    )

                    # Apply keyword filter
                    if alert.keywords:
                        keyword_queries = Q()
                        for keyword in [k.strip() for k in alert.keywords.split(',') if k.strip()]:
                            keyword_queries |= Q(title__icontains=keyword)
                            keyword_queries |= Q(description__icontains=keyword)
                            keyword_queries |= Q(company_name__icontains=keyword)
                        matching_jobs = matching_jobs.filter(keyword_queries)

                    # Apply category filter
                    if alert.categories.exists():
                        matching_jobs = matching_jobs.filter(category__in=alert.categories.all())

                    # Apply location filter
                    if alert.locations:
                        location_queries = Q()
                        for loc in [l.strip() for l in alert.locations.split(',') if l.strip()]:
                            location_queries |= Q(location__icontains=loc)
                        matching_jobs = matching_jobs.filter(location_queries)

                    # Apply job type filter
                    if alert.job_types:
                        job_type_queries = Q()
                        for jt in [j.strip() for j in alert.job_types.split(',') if j.strip()]:
                            job_type_queries |= Q(job_type__iexact=jt) # Use iexact for case-insensitive match
                        matching_jobs = matching_jobs.filter(job_type_queries)

                    # Exclude jobs that have already expired (if expiry date is set)
                    matching_jobs = matching_jobs.filter(
                        Q(job_expiry_date__isnull=True) | Q(job_expiry_date__gte=now)
                    )

                    # Ensure unique jobs in case of multiple filter matches
                    matching_jobs = matching_jobs.distinct()

                    if matching_jobs.exists():
                        self.stdout.write(f"  Found {matching_jobs.count()} new jobs for alert '{alert.alert_name}' for user {alert.user.email}")

                        # Prepare context for email template
                        context = {
                            'user': alert.user,
                            'alert_name': alert.alert_name,
                            'new_jobs': matching_jobs,
                            'portal_name': 'JobPortal', # Customize your portal name
                            'unsubscribe_link': f"{settings.BASE_URL}/applicant/job-alerts/", # Example unsubscribe link
                            'settings': settings, # Pass settings to access BASE_URL in template
                        }

                        # Render HTML email
                        html_message = render_to_string('emails/job_alert_email.html', context)
                        plain_message = strip_tags(html_message) # Fallback plain text

                        try:
                            send_mail(
                                subject=f"Your Job Alert: New {alert.alert_name} Jobs!",
                                message=plain_message,
                                from_email=settings.DEFAULT_FROM_EMAIL,
                                recipient_list=[alert.user.email],
                                html_message=html_message,
                                fail_silently=False,
                            )
                            self.stdout.write(self.style.SUCCESS(f"  Sent alert email to {alert.user.email} for '{alert.alert_name}'"))
                        except Exception as e:
                            self.stdout.write(self.style.ERROR(f"  Failed to send email to {alert.user.email} for '{alert.alert_name}': {e}"))
                            # Log the error. In a production environment, consider more robust error reporting.

                    # Update last_sent timestamp for the alert, regardless of whether jobs were found or email sent
                    # This ensures the alert doesn't re-send the same batch of jobs repeatedly if no new jobs are found
                    alert.last_sent = now
                    alert.save(update_fields=['last_sent'])
                    self.stdout.write(f"  Updated last_sent for alert '{alert.alert_name}' to {now}")

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"An error occurred during {frequency} alerts processing: {e}"))
                # Log the error. In a production environment, consider more advanced error reporting.
            self.stdout.write(self.style.HTTP_INFO(f'--- Finished processing for {frequency} alerts ---'))

        self.stdout.write(self.style.SUCCESS('Job alert processing completed.'))
        self.stdout.write(self.style.WARNING('Note: Emails are sent synchronously by this command. For large scale, consider a task queue like Celery.'))

