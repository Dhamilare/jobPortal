from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils import timezone
import uuid
from django.conf import settings

# -------------------------------
# User Manager
# -------------------------------
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email address is required')
        email = self.normalize_email(email)
        extra_fields.setdefault('is_active', False)  # Users must verify email
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.update({
            'is_staff': True,
            'is_superuser': True,
            'is_active': True,
            'is_applicant': False,
            'is_moderator': False,
        })

        if not extra_fields['is_staff'] or not extra_fields['is_superuser']:
            raise ValueError('Superuser must have is_staff=True and is_superuser=True.')
        return self.create_user(email, password, **extra_fields)

# -------------------------------
# Custom User Model
# -------------------------------
class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    is_applicant = models.BooleanField(default=True)
    is_moderator = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = CustomUserManager()

    def __str__(self):
        return self.email

# -------------------------------
# Job Category
# -------------------------------
class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    class Meta:
        verbose_name_plural = "Categories"

    def __str__(self):
        return self.name

# -------------------------------
# Job Posting
# -------------------------------
class Job(models.Model):
    JOB_TYPE_CHOICES = [
        ('Full-time', 'Full-time'),
        ('Part-time', 'Part-time'),
        ('Contract', 'Contract'),
        ('Temporary', 'Temporary'),
        ('Internship', 'Internship'),
    ]

    title = models.CharField(max_length=200)
    description = models.TextField()
    company_name = models.CharField(max_length=150)
    location = models.CharField(max_length=100)
    job_type = models.CharField(max_length=50, choices=JOB_TYPE_CHOICES, default='Full-time')
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, related_name='jobs')
    posted_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='posted_jobs')
    date_posted = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    job_expiry_date = models.DateTimeField(null=True, blank=True, help_text="Optional: Date when this job listing expires.")
    external_application_url = models.URLField(
        max_length=500,
        blank=True,
        help_text="External link for job application if not processed internally."
    )

    def __str__(self):
        return f"{self.title} at {self.company_name}"

# -------------------------------
# Job Application
# -------------------------------
class Application(models.Model):
    STATUS_CHOICES = [
        ('Clicked Apply Link', 'Clicked Apply Link'),
        ('Reviewed', 'Reviewed'),
        ('Interview', 'Interview Scheduled'),
        ('Rejected', 'Rejected'),
        ('Hired', 'Hired'),
    ]

    applicant = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='applications')
    job = models.ForeignKey(Job, on_delete=models.CASCADE, related_name='applications')
    application_date = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Clicked Apply Link')
    cover_letter = models.TextField(blank=True, null=True)

    class Meta:
        unique_together = ('applicant', 'job')
        ordering = ['-application_date']

    def __str__(self):
        return f"{self.applicant.username} → {self.job.title}"

# -------------------------------
# Email Verification Token
# -------------------------------
class EmailVerificationToken(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='verification_token')
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.pk:
            self.expires_at = timezone.now() + timezone.timedelta(hours=24)
        super().save(*args, **kwargs)

    def is_valid(self):
        return timezone.now() < self.expires_at

    def __str__(self):
        return f"Token for {self.user.email}"
    

class SavedJob(models.Model):
    """
    Model to track jobs saved by applicants.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='saved_jobs')
    job = models.ForeignKey(Job, on_delete=models.CASCADE, related_name='saved_by')
    saved_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'job') # A user can save a job only once
        ordering = ['-saved_at'] # Order by most recently saved

    def __str__(self):
        return f"{self.user.username} saved {self.job.title}"
    

class JobAlert(models.Model):
    FREQUENCY_CHOICES = [
        ('Daily', 'Daily'),
        ('Weekly', 'Weekly'),
        ('Bi-Weekly', 'Bi-Weekly'),
        ('Monthly', 'Monthly'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='job_alerts')
    alert_name = models.CharField(max_length=255, help_text="A name for your alert (e.g., 'Remote Python Jobs')")
    keywords = models.CharField(max_length=255, blank=True, null=True, help_text="Comma-separated keywords (e.g., 'Python, Django, API')")
    categories = models.ManyToManyField(Category, blank=True, help_text="Select categories for the alert")
    locations = models.CharField(max_length=255, blank=True, null=True, help_text="Comma-separated locations (e.g., 'London, Remote, New York')")
    job_types = models.CharField(max_length=255, blank=True, null=True, help_text="Comma-separated job types (e.g., 'Full-time, Remote')")
    frequency = models.CharField(max_length=50, choices=FREQUENCY_CHOICES, default='Weekly')
    created_at = models.DateTimeField(auto_now_add=True)
    last_sent = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"Alert: {self.alert_name} for {self.user.username}"

    class Meta:
        unique_together = ('user', 'alert_name') # A user can't have two alerts with the same name
