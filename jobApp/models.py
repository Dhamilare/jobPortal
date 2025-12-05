from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils import timezone
import uuid
from django.conf import settings
from django.core.validators import RegexValidator
from django.template.defaultfilters import slugify
import string, random
from django_ckeditor_5.fields import CKEditor5Field
from django.db.models.signals import post_save
from django.dispatch import receiver
from PyPDF2 import PdfReader
import docx2txt
import os

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
    slug = models.SlugField(unique=True, max_length=200, null=True, blank=True)

    class Meta:
        verbose_name_plural = "Categories"

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super(Category, self).save(*args, **kwargs)

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
        ('Remote', 'Remote'),
    ]

    APPLICATION_METHOD_CHOICES = [
        ('Internal', 'Internal Form Application'),
        ('External', 'External Link Application'),
    ]

    title = models.CharField(max_length=200)
    description = CKEditor5Field(config_name='default')
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
        null=True,
        help_text="External link for job application. Required if Application Method is External."
    )
    application_method = models.CharField(
        max_length=50,
        choices=APPLICATION_METHOD_CHOICES,
        default='Internal',
        help_text="Choose the method applicants use to apply for this job."
    )
    slug = models.SlugField(unique=True, max_length=200, null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.title)
        super(Job, self).save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.title} at {self.company_name}"

# -------------------------------
# Job Application
# -------------------------------
class Application(models.Model):
    STATUS_CHOICES = [
        ('Submitted', 'Application Submitted'),
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

    # Personal Information
    full_name = models.CharField(max_length=255, help_text="Applicant's full name.")
    email_address = models.EmailField(help_text="Applicant's primary email address.")
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    GENDER_CHOICES = [('M', 'Male'), ('F', 'Female'), ('O', 'Other'), ('P', 'Prefer not to say')]
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, blank=True, null=True)

    # Resume/Supporting Documents (File fields for CV/Resume)
    submitted_resume = models.FileField(
        upload_to='job_applications/resumes/%Y/%m/',
        help_text="Applicant's submitted resume/CV file.",
        blank=True,
        null=True
    )

    availability_notice_period = models.CharField(
        max_length=255, 
        blank=True, 
        null=True, 
        help_text="e.g., '2 weeks notice' or 'Immediate'"
    )
    
    expected_salary = models.CharField(
        max_length=255, 
        blank=True, 
        null=True, 
        help_text="e.g., '€50,000'"
    )

    class Meta:
        unique_together = ('applicant', 'job')
        ordering = ['-application_date']

    def __str__(self):
        return f"{self.applicant.username} → {self.job.title}"


# -------------------------------
# Email Verification Token
# -------------------------------
class EmailVerificationToken(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='verification_tokens'
    )
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

    class Meta:
        indexes = [
            models.Index(fields=['expires_at']),
        ]
        verbose_name = "Email Verification Token"
        verbose_name_plural = "Email Verification Tokens"
    

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
        return f"{self.user.username}'s {self.alert_name} ({self.frequency})"

    class Meta:
        unique_together = ('user', 'alert_name')



class Recruiter(models.Model):
    company_name = models.CharField(
        max_length=255,
        verbose_name="Company Name"
    )

    address = models.TextField(
        verbose_name="Company Address"
    )

    phone_number = models.CharField(
        max_length=20,
        verbose_name="Phone Number",
        validators=[
            RegexValidator(
                regex=r'^\+?\d{7,15}$',
                message="Enter a valid phone number (11 digits, may include +)."
            )
        ]
    )

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='recruiter_profile',
        verbose_name="User Account"
    )

    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created At")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Updated At")

    def __str__(self):
        return f"{self.company_name} ({self.user.email})"

    class Meta:
        verbose_name = "Recruiter"
        verbose_name_plural = "Recruiters"
        ordering = ['company_name']
        indexes = [
            models.Index(fields=['company_name']),
            models.Index(fields=['phone_number'])
        ]


class Subscriber(models.Model):
    """
    Model to store email addresses for newsletter subscriptions.
    """
    email = models.EmailField(unique=True, help_text="The subscriber's email address.")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email

    class Meta:
        verbose_name_plural = "Subscribers"
        ordering = ['-created_at']



# -------------------------------
# Blog Models
# -------------------------------
class BlogCategory(models.Model):
    """
    Model for blog post categories.
    """
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    class Meta:
        verbose_name_plural = "Blog Categories"

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)


def generate_unique_slug(model, title, slug_field_name="slug"):
    base_slug = slugify(title)
    slug = base_slug
    ModelClass = model.__class__
    counter = 0

    while ModelClass.objects.filter(**{slug_field_name: slug}).exists():
        counter += 1
        rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        slug = f"{base_slug}-{rand_suffix}"

        if counter > 10:
            break

    return slug


class Post(models.Model):
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=250, unique=True, blank=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='blog_posts')
    content = CKEditor5Field(config_name='default')
    image = models.ImageField(
        upload_to='blog_images/',
        blank=True,
        null=True,
        help_text="Optional image for the blog post."
    )
    category = models.ForeignKey(
        BlogCategory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='blog_posts'
    )
    publish_date = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-publish_date']
        indexes = [
            models.Index(fields=['-publish_date']),
        ]

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = generate_unique_slug(self, self.title)
        super().save(*args, **kwargs)


class Comment(models.Model):
    """
    Model for comments on a blog post.
    """
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='blog_comments')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"Comment by {self.author.username} on {self.post.title} ({self.content[:20]}...)"
    


# -------------------------------
# Applicant Profile
# -------------------------------

class ApplicantProfile(models.Model):
    """
    Stores applicant-specific data, including their primary resume
    and the AI-parsed analysis.
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='applicant_profile' # This related_name is very important
    )
    
    # --- Resume Fields ---
    resume = models.FileField(
        upload_to='resumes/%Y/%m/',
        blank=True,
        null=True,
        help_text="The user's primary resume file (PDF, DOCX)."
    )
    resume_text = models.TextField(
        blank=True,
        help_text="Raw text extracted from the resume file (populated by a background task)."
    )
    
    parsed_experience = models.JSONField(
        blank=True,
        null=True,
        help_text="Structured experience extracted by the AI."
    )
    parsed_skills = models.JSONField(
        blank=True,
        null=True,
        help_text="Skills extracted by the AI (e.g., ['Python', 'Django', 'React'])."
    )
    parsed_summary = models.TextField(
        blank=True,
        help_text="AI-generated summary of the applicant's profile."
    )

    last_updated = models.DateTimeField(auto_now=True)

    def extract_resume_text(self):
        """Extract text content from the uploaded resume (PDF or DOCX)."""
        if not self.resume:
            return ""

        try:
            ext = os.path.splitext(self.resume.name)[1].lower()

            if ext == ".pdf":
                with open(self.resume.path, "rb") as f:
                    reader = PdfReader(f)
                    text = "".join(page.extract_text() or "" for page in reader.pages)
                    return text.strip()

            elif ext == ".docx":
                text = docx2txt.process(self.resume.path)
                return text.strip()

            else:
                return "Unsupported file format. Please upload a PDF or DOCX."

        except Exception as e:
            print(f"Error extracting text from resume: {e}")
            return ""

    def __str__(self):
        return f"Profile for {self.user.email}"


# --- Signal to auto-create profile ---
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_or_update_applicant_profile(sender, instance, created, **kwargs):
    """
    Automatically create an ApplicantProfile when a new user is created
    and is_applicant is True.
    """
    if instance.is_applicant and created:
        ApplicantProfile.objects.create(user=instance)
    elif instance.is_applicant:
        # If user exists, just save their profile (in case of updates)
        # Use hasattr to prevent errors if profile doesn't exist for some reason
        if hasattr(instance, 'applicant_profile'):
            instance.applicant_profile.save()
        else:
            ApplicantProfile.objects.create(user=instance)