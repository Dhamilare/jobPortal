from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils import timezone
import uuid

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
