from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from django.http import HttpResponse
from django.db import IntegrityError, models
from django.db.models.functions import TruncDay
from datetime import timedelta
import csv, io
from django.contrib import messages 
from itertools import chain
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from datetime import datetime
import json

from .forms import *
from .models import *

# ----------------------------
# Role-based Access Decorators
# ----------------------------
def role_required(role_check, login_url='login'):
    return user_passes_test(role_check, login_url=login_url)

def applicant_required(view):
    return role_required(lambda u: u.is_authenticated and u.is_applicant)(view)

def moderator_required(view):
    return role_required(lambda u: u.is_authenticated and (u.is_moderator or u.is_staff))(view)

def staff_required(view):
    return role_required(lambda u: u.is_authenticated and u.is_staff)(view)

# ----------------------------
# Public Views
# ----------------------------
def home_view(request):
    verified_jobs = Job.objects.filter(is_active=True).order_by('-date_posted')[:6]
    return render(request, 'home.html', {'verified_jobs': verified_jobs})

def about_view(request):
    return render(request, 'about.html')

def applicant_register(request):
    if request.user.is_authenticated:
        return redirect('home')

    form = ApplicantRegistrationForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        user = form.save()
        token = EmailVerificationToken.objects.create(user=user)
        verification_link = request.build_absolute_uri(
            reverse('email_verification_confirm', args=[token.token])
        )

        html_message = render_to_string('email_verification.html', {
            'user': user,
            'verification_link': verification_link,
            'current_year': datetime.now().year,
        })
        plain_message = strip_tags(html_message)

        send_mail(
            subject='Verify your JobPortal account',
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
        )

        messages.success(
            request,
            f'Registration successful! A verification link has been sent to {user.email}. '
            'Please check your inbox (and spam folder) to activate your account.'
        )
        return redirect('login')

    return render(request, 'accounts/register.html', {'form': form})

def email_verification_confirm(request, token):
    try:
        token_obj = EmailVerificationToken.objects.get(token=token)
    except EmailVerificationToken.DoesNotExist:
        messages.error(request, 'Invalid verification link. Please register again or request a new link.')
        return redirect('register')

    if not token_obj.is_valid():
        token_obj.delete()
        messages.error(request, 'Verification link has expired. Please register again or request a new link.')
        return redirect('register')

    user = token_obj.user
    if not user.is_active:
        user.is_active = True
        user.save()
    token_obj.delete()
    messages.success(request, f'Your email ({user.email}) has been successfully verified! You can now log in.')
    return redirect('login')

def user_login(request):
    if request.user.is_authenticated:
        return redirect('applicant_dashboard' if request.user.is_applicant else 'moderator_dashboard')

    form = LoginForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        login(request, form.user)
        messages.success(request, f'Welcome back, {request.user.username}!')
        return redirect('applicant_dashboard' if form.user.is_applicant else 'moderator_dashboard')
    return render(request, 'accounts/login.html', {'form': form})

@login_required
def user_logout(request):
    messages.info(request, 'You have been successfully logged out.')
    logout(request)
    return redirect('login')

# ----------------------------
# Job Views
# ----------------------------
def job_list_view(request):
    jobs = Job.objects.filter(is_active=True).order_by('-date_posted')
    query, category, job_type = request.GET.get('q'), request.GET.get('category'), request.GET.get('job_type')

    if query:
        jobs = jobs.filter(
            models.Q(title__icontains=query) |
            models.Q(description__icontains=query) |
            models.Q(company_name__icontains=query) |
            models.Q(location__icontains=query)
        )
    if category:
        jobs = jobs.filter(category__name__iexact=category)
    if job_type:
        jobs = jobs.filter(job_type__iexact=job_type)

    context = {
        'jobs': jobs,
        'categories': Category.objects.all(),
        'job_types': [jt[0] for jt in Job.JOB_TYPE_CHOICES],
        'current_query': query or '',
        'current_category': category or '',
        'current_job_type': job_type or '',
    }
    return render(request, 'job_list.html', context)

def job_detail_view(request, job_id):
    job = get_object_or_404(Job, pk=job_id)
    has_applied = False
    if request.user.is_authenticated and request.user.is_applicant:
        has_applied = Application.objects.filter(applicant=request.user, job=job).exists()

    return render(request, 'job_detail.html', {'job': job, 'has_applied': has_applied})

@login_required
@applicant_required
def job_apply_link_redirect(request, job_id):
    job = get_object_or_404(Job, pk=job_id)
    if not job.external_application_url:
        messages.error(request, 'This job does not currently have an external application link configured by the employer.')
        return redirect('job_detail', job_id=job.id) # Redirect back to job detail with error

    try:
        Application.objects.create(applicant=request.user, job=job)
        messages.success(request, f'You have successfully marked your interest in "{job.title}". Redirecting to external application site.')
    except IntegrityError:
        messages.info(request, f'You have already applied for "{job.title}".')
    return redirect(job.external_application_url)

# ----------------------------
# Applicant Views
# ----------------------------
@applicant_required
def applicant_dashboard(request):
    apps = Application.objects.filter(applicant=request.user)
    context = {
        'total_applied': apps.count(),
        'offers_received': apps.filter(status='Hired').count(),
        'pending_applications': apps.exclude(status__in=['Hired', 'Rejected']).count(),
        'recent_applications': apps.order_by('-application_date')[:5],
    }
    return render(request, 'applicants/dashboard.html', context)

@applicant_required
def applicant_profile_update(request):
    form = ApplicantProfileUpdateForm(request.POST or None, instance=request.user)
    if request.method == 'POST' and form.is_valid():
        form.save()
        messages.success(request, 'Your profile has been updated successfully!')
        return redirect('applicant_dashboard')
    return render(request, 'applicants/profile_update.html', {'form': form})

@applicant_required
def applicant_password_change(request):
    form = CustomPasswordChangeForm(user=request.user, data=request.POST or None)
    if request.method == 'POST' and form.is_valid():
        form.save()
        update_session_auth_hash(request, form.user)
        messages.success(request, 'Your password has been changed successfully!')
        return redirect('applicant_dashboard')
    return render(request, 'applicants/password_change.html', {'form': form})

@applicant_required
def applicant_email_change(request):
    form = ApplicantEmailChangeForm(request.POST or None, user=request.user)
    if request.method == 'POST' and form.is_valid():
        user = form.save()
        logout(request)
        EmailVerificationToken.objects.filter(user=user).delete()
        token = EmailVerificationToken.objects.create(user=user)
        link = request.build_absolute_uri(reverse('email_verification_confirm', args=[token.token]))

        html_message = render_to_string('email_change__verification.html', {
            'user': user,
            'verification_link': link,
            'current_year': datetime.now().year,
        })
        plain_message = strip_tags(html_message)

        send_mail(
            subject='Verify your new JobPortal email',
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
        )

        messages.success(request, f'Your email address has been updated to {user.email}. A new verification link has been sent to this address. Please verify your new email to reactivate your account.')
        return redirect('login')
    return render(request, 'applicants/email_change.html', {'form': form})


# ----------------------------
# Moderator Views
# ----------------------------
@moderator_required
def moderator_dashboard(request):
    now = timezone.now()
    context = {
        'total_jobs': Job.objects.count(),
        'total_applicants': CustomUser.objects.filter(is_applicant=True).count(),
        'applications_24hrs': Application.objects.filter(application_date__gte=now - timedelta(hours=24)).count(),
        'verified_users': CustomUser.objects.filter(is_active=True).count(),
    }

    recent_jobs = Job.objects.select_related('posted_by').order_by('-date_posted')[:5]
    recent_applicants = CustomUser.objects.order_by('-date_joined')[:5]
    recent_applications = Application.objects.select_related('applicant', 'job').order_by('-application_date')[:5]

    activity_list = []

    for job in recent_jobs:
        activity_list.append({
            'timestamp': job.date_posted,
            'type': 'job_created',
            'message': f'Job "{job.title}" created by {job.posted_by.username}.'
        })

    for applicant in recent_applicants:
        activity_list.append({
            'timestamp': applicant.date_joined,
            'type': 'applicant_registered',
            'message': f'Applicant "{applicant.username}" registered.'
        })

    for app in recent_applications:
        activity_list.append({
            'timestamp': app.application_date,
            'type': 'job_applied',
            'message': f'Applicant "{app.applicant.username}" clicked apply for "{app.job.title}".'
        })

    activity_list.sort(key=lambda x: x['timestamp'], reverse=True)

    context['recent_activity_log'] = activity_list[:10]

    return render(request, 'moderator/dashboard.html', context)

@moderator_required
def job_list_create(request):
    form = JobForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        job = form.save(commit=False)
        job.posted_by = request.user
        job.save()
        messages.success(request, f'Job "{job.title}" created successfully!')
        return redirect('job_list_create')
    jobs = Job.objects.all().order_by('-date_posted')
    return render(request, 'moderator/job_list_create.html', {'jobs': jobs, 'form': form})

@moderator_required
def job_update_delete(request, job_id):
    job = get_object_or_404(Job, pk=job_id)
    form = JobForm(request.POST or None, instance=job)
    if request.method == 'POST':
        if 'delete' in request.POST:
            job_title = job.title
            job.delete()
            messages.success(request, f'Job "{job_title}" deleted successfully!')
            return redirect('job_list_create')
        elif form.is_valid():
            form.save()
            messages.success(request, f'Job "{job.title}" updated successfully!')
            return redirect('job_list_create')
    return render(request, 'moderator/job_update_delete.html', {'form': form, 'job': job})

@moderator_required
def moderator_report_view(request):
    # Chart 1: Applicant Sign-ups Over Time
    signups_data = CustomUser.objects.filter(is_applicant=True).annotate(
        date=TruncDay('date_joined')
    ).values('date').annotate(count=models.Count('id')).order_by('date')

    # Chart 2: Jobs by Category
    jobs_by_category = Category.objects.annotate(
        job_count=models.Count('jobs')
    ).values('name', 'job_count').order_by('-job_count')

    # Chart 3: Top Jobs by Application Clicks
    top_jobs_applied = Job.objects.annotate(
        application_count=models.Count('applications')
    ).values('title', 'application_count').order_by('-application_count')[:5]

    context = {
        'signups_data_json': json.dumps(list(signups_data), default=str),  # date to string
        'jobs_by_category_json': json.dumps(list(jobs_by_category), default=str),
        'top_jobs_applied_json': json.dumps(list(top_jobs_applied), default=str),
    }

    return render(request, 'moderator/moderator_reports.html', context)

# ----------------------------
# Staff Views
# ----------------------------
@staff_required
def is_staff_create_moderator(request):
    form = ModeratorCreationForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.save()
        messages.success(request, f'Moderator account for "{user.username}" created successfully!')
        return redirect('is_staff_create_moderator')
    return render(request, 'staff/is_staff_create_moderator.html', {'form': form})

@staff_required
def is_staff_export_applicants_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="applicants_export.csv"'
    writer = csv.writer(response)
    writer.writerow(['ID', 'Username', 'Email', 'First Name', 'Last Name', 'Date Joined', 'Is Active'])
    for applicant in CustomUser.objects.filter(is_applicant=True).order_by('date_joined'):
        writer.writerow([
            applicant.id, applicant.username, applicant.email,
            applicant.first_name, applicant.last_name,
            applicant.date_joined.strftime('%Y-%m-%d %H:%M:%S'),
            'Yes' if applicant.is_active else 'No'
        ])
    messages.success(request, 'Applicant data exported successfully to CSV!')
    return response

# New Category Management Views
@moderator_required
def manage_categories(request):
    form = CategoryForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        try:
            form.save()
            messages.success(request, f'Category "{form.cleaned_data["name"]}" created successfully!')
            return redirect('manage_categories')
        except IntegrityError:
            messages.error(request, 'A category with this name already exists.')
    
    categories = Category.objects.all().order_by('name')
    return render(request, 'moderator/manage_categories.html', {'categories': categories, 'form': form})

@moderator_required
def category_update_delete(request, category_id):
    category = get_object_or_404(Category, pk=category_id)
    form = CategoryForm(request.POST or None, instance=category)

    if request.method == 'POST':
        if 'delete' in request.POST:
            category_name = category.name
            try:
                category.delete()
                messages.success(request, f'Category "{category_name}" deleted successfully!')
                return redirect('manage_categories')
            except models.ProtectedError:
                messages.error(request, f'Cannot delete category "{category_name}" because it has associated jobs. Please reassign or delete jobs in this category first.')
                return redirect('category_update_delete', category_id=category.id)
        elif form.is_valid():
            try:
                form.save()
                messages.success(request, f'Category "{category.name}" updated successfully!')
                return redirect('manage_categories')
            except IntegrityError:
                messages.error(request, 'A category with this name already exists.')
    
    return render(request, 'moderator/category_update_delete.html', {'form': form, 'category': category})


@moderator_required
def job_bulk_upload_csv(request):
    upload_form = JobCSVUploadForm(request.POST or None, request.FILES or None)
    
    if request.method == 'POST' and upload_form.is_valid():
        csv_file = request.FILES['csv_file']
        file_data = csv_file.read().decode('utf-8')
        csv_reader = csv.reader(io.StringIO(file_data))

        jobs_created = 0
        jobs_updated = 0
        jobs_processed = 0
        errors = []

        expected_headers = [
            'title', 'company name', 'location', 'job type',
            'category name', 'external application url',
            'description', 'is active'
        ]
        header_map = {
            'title': 'title',
            'company name': 'company_name',
            'location': 'location',
            'job type': 'job_type',
            'category name': 'category',
            'external application url': 'external_application_url',
            'description': 'description',
            'is active': 'is_active',
        }
        job_type_choices = [choice[0].lower() for choice in Job.JOB_TYPE_CHOICES]

        headers = []
        for i, row in enumerate(csv_reader):
            if i == 0:
                headers = [h.strip().lower() for h in row]
                missing_headers = [col for col in expected_headers if col not in headers]
                if missing_headers:
                    messages.error(request, f"Missing headers: {', '.join(missing_headers)}")
                    return redirect('job_list_create')
                
                unexpected_columns = [col for col in headers if col not in expected_headers]
                if unexpected_columns:
                    messages.warning(request, f"Note: Ignored extra columns: {', '.join(unexpected_columns)}")
                continue

            try:
                row_data = dict(zip(headers, row))
            except Exception as e:
                errors.append(f"Row {i+1}: Malformed row structure - {e}")
                continue

            job_data = {}
            row_errors = []
            jobs_processed += 1

            for csv_col, model_field in header_map.items():
                value = row_data.get(csv_col, '').strip()

                if model_field == 'category':
                    if value:
                        try:
                            job_data['category'] = Category.objects.get(name__iexact=value)
                        except Category.DoesNotExist:
                            row_errors.append(f"Row {i+1}: Category '{value}' does not exist.")
                    else:
                        job_data['category'] = None

                elif model_field == 'job_type':
                    if value.lower() in job_type_choices:
                        job_data['job_type'] = value
                    else:
                        row_errors.append(
                            f"Row {i+1}: Invalid job type '{value}'. Must be one of: "
                            f"{', '.join([jt[0] for jt in Job.JOB_TYPE_CHOICES])}"
                        )

                elif model_field == 'is_active':
                    job_data['is_active'] = value.lower() == 'true'

                elif model_field == 'external_application_url':
                    if value and not (value.startswith('http://') or value.startswith('https://')):
                        row_errors.append(f"Row {i+1}: Invalid URL '{value}'. Must start with http:// or https://.")
                    job_data[model_field] = value

                else:
                    if model_field in ['title', 'company_name', 'location'] and not value:
                        row_errors.append(f"Row {i+1}: '{csv_col}' cannot be empty.")
                    job_data[model_field] = value

            if row_errors:
                errors.extend(row_errors)
                continue

            try:
                job, created = Job.objects.update_or_create(
                    title=job_data['title'],
                    company_name=job_data['company_name'],
                    location=job_data['location'],
                    defaults={
                        'job_type': job_data['job_type'],
                        'category': job_data['category'],
                        'external_application_url': job_data['external_application_url'],
                        'description': job_data['description'],
                        'is_active': job_data['is_active'],
                        'posted_by': request.user,
                    }
                )
                if created:
                    jobs_created += 1
                else:
                    jobs_updated += 1
            except Exception as e:
                errors.append(f"Row {i+1}: Failed to save job '{job_data.get('title')}' - {e}")

        # Final messaging
        if errors:
            for e in errors[:10]:  # Show only first 10 errors
                messages.error(request, e)
            if len(errors) > 10:
                messages.warning(request, f"And {len(errors) - 10} more errors hidden. Please check the file carefully.")
            messages.warning(request, f"Processed {jobs_processed} rows with {len(errors)} error(s). {jobs_created} created, {jobs_updated} updated.")
        else:
            messages.success(request, f"CSV upload successful! {jobs_created} jobs created, {jobs_updated} jobs updated.")

        return redirect('job_list_create')

    # GET or invalid form
    jobs = Job.objects.all().order_by('-date_posted')
    return render(request, 'moderator/job_list_create.html', {
        'jobs': jobs,
        'form': JobForm(),
        'upload_form': upload_form,
    })

@moderator_required
def job_bulk_upload_csv_sample(request):
    """
    Provides a downloadable sample CSV template for bulk job uploads.
    """
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="job_upload_sample.csv"'

    writer = csv.writer(response)
    # Define the headers that the bulk upload expects
    headers = [
        'Title', 'Company Name', 'Location', 'Job Type',
        'Category Name', 'External Application URL', 'Description', 'Is Active'
    ]
    writer.writerow(headers)

    # Add a sample row (optional, but very helpful for users)
    writer.writerow([
        'Software Engineer', 'Acme Corp', 'Remote', 'Full-time',
        'Technology', 'https://acmecorp.com/careers/software-engineer',
        'Develop and maintain software applications.', 'True'
    ])
    writer.writerow([
        'Marketing Specialist', 'Global Brands', 'New York, NY', 'Full-time',
        'Marketing', 'https://globalbrands.com/jobs/marketing-specialist',
        'Execute marketing campaigns and analyze performance.', 'True'
    ])
    writer.writerow([
        'Customer Support Intern', 'Startup Innovations', 'San Francisco, CA', 'Internship',
        'Customer Service', '', # Empty URL for this example
        'Assist customers with product inquiries and support.', 'False'
    ])

    return response