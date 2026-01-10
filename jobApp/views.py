from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from django.http import HttpResponse, HttpResponseBadRequest
from django.db import IntegrityError, models
from django.db.models.functions import TruncDay, Cast
from datetime import timedelta
from django.db.models import DateField
from django.utils.timezone import now
import csv, io
from django.contrib import messages 
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from datetime import date, datetime
import json
from django.http import HttpResponseRedirect
from .forms import *
from .models import *
from django.db.models import Q
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.templatetags.static import static
from django.http import Http404, HttpRequest
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes
from django.views.decorators.http import require_http_methods
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.http import JsonResponse
from django.core.validators import validate_email
import logging
logger = logging.getLogger(__name__)
from .utils import *
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import requests
from decouple import config
from django.core.files.storage import default_storage
from django.utils.safestring import mark_safe
from django.http import FileResponse
import mimetypes
from django.contrib.sites.models import Site
import time
from requests.exceptions import HTTPError, RequestException
from django.views.decorators.http import require_POST
import hmac
import hashlib


def robots_txt(request):
    lines = [
        "User-agent: Mediapartners-Google",
        "Allow: /",
        "",
        "User-agent: *",
        "Allow: /",
        "Disallow: /admin/",
        "Sitemap: https://readyremotejob.com/sitemap.xml",
    ]
    return HttpResponse("\n".join(lines), content_type="text/plain")


def sitemap_xml(request):
    """Generate a sitemap for all active job listings and homepage."""
    now = timezone.now()
    
    # Only include active jobs that haven't expired
    jobs = Job.objects.filter(is_active=True).filter(
        job_expiry_date__gt=now
    ) | Job.objects.filter(is_active=True, job_expiry_date__isnull=True)

    # Start XML
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
        # Homepage
        f'  <url><loc>https://readyremotejob.com/</loc><lastmod>{now.date()}</lastmod></url>',
    ]

    # Add job URLs
    for job in jobs:
        url = f"https://readyremotejob.com/jobs/{job.slug}/"
        lastmod = job.job_expiry_date.date() if job.job_expiry_date else job.date_posted.date()
        lines.append(f'  <url><loc>{url}</loc><lastmod>{lastmod}</lastmod></url>')

    # Close XML
    lines.append('</urlset>')

    return HttpResponse("\n".join(lines), content_type="application/xml")

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


def send_custom_password_reset_email(user, request):
    current_site = get_current_site(request)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    context = {
        "protocol": "https" if request.is_secure() else "http",
        "domain": current_site.domain,
        "site_name": current_site.name, # Added for branding
        "uid": uid,
        "token": token,
        "user": user
    }

    send_templated_email(
        template_name="accounts/password_reset_email.html",
        subject="Job Portal Password Reset Request",
        recipient_list=[user.email],
        context=context
    )
    

def custom_password_reset(request):
    if request.method == "POST":
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            users = User.objects.filter(email=email, is_active=True)
            if users.exists():
                for user in users:
                    send_custom_password_reset_email(user, request)
            return redirect('password_reset_done')
            
    else:
        form = PasswordResetForm()

    context = {
        "form": form,
    }
    return render(request, "accounts/password_reset.html", context)


# ----------------------------
# Public Views
# ----------------------------
def home_view(request):
    verified_jobs = Job.objects.filter(is_active=True).order_by('-date_posted')[:6]

    now = timezone.now()
    for job in verified_jobs:
        time_since_posted = now - job.date_posted
        job.is_hot_job = time_since_posted < timedelta(hours=24)
        
        job.is_expired = False
        if job.job_expiry_date and job.job_expiry_date < now:
            job.is_expired = True

    # Fetch only the 3 most recent PUBLISHED blog posts (no future posts)
    blog_posts = Post.objects.filter(
        publish_date__lte=now
    ).order_by('-publish_date')[:3]

    context = {
        'verified_jobs': verified_jobs,
        'blog_posts': blog_posts,
    }

    return render(request, 'home.html', context)

def about_view(request):
    return render(request, 'about.html')


def applicant_register(request):
    if request.user.is_authenticated:
        return redirect('home')

    form = ApplicantRegistrationForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        user = form.save()
        token = EmailVerificationToken.objects.create(user=user)

        # Build the absolute URL correctly
        current_site = get_current_site(request)
        domain = current_site.domain
        protocol = 'https'
        
        verification_path = reverse('email_verification_confirm', args=[token.token])
        verification_link = f"{protocol}://{domain}{verification_path}"

        subject = 'Verify Your Account'
        context = {
            'user': user,
            'verification_link': verification_link,
            'current_year': timezone.now().year
        }

        send_templated_email(
            'email_verification.html',
            subject,
            [user.email],
            context
        )

        messages.success(
            request,
            f'Registration successful! A verification link has been sent to {user.email}. '
            'Please check your inbox (and spam folder) to activate your account.'
        )
        return redirect('login') 

    return render(request, 'accounts/register.html', {'form': form})


@require_http_methods(["GET"])
def email_verification_confirm(request, token):
    """
    Confirms email verification using a secure token.
    Activates the user if token is valid and not expired.
    """
    try:
        token_obj = EmailVerificationToken.objects.select_related('user').get(token=token)
    except EmailVerificationToken.DoesNotExist:
        messages.error(request, 'Invalid verification link. Please register again or request a new link.')
        return redirect('register')

    if not token_obj.is_valid():
        token_obj.delete()
        messages.error(request, 'Verification link has expired. Please register again or request a new link.')
        return redirect('register')

    user = token_obj.user
    with transaction.atomic():
        if not user.is_active:
            user.is_active = True
            user.save(update_fields=['is_active'])
        token_obj.delete()

    messages.success(request, f'Your email ({user.email}) has been successfully verified! You can now log in.')
    return redirect('login')


def user_login(request):
    if request.user.is_authenticated:
        return redirect('applicant_dashboard' if request.user.is_applicant else 'moderator_dashboard')

    form = LoginForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        login(request, form.user)
        messages.success(request, f'Welcome back, {request.user.get_full_name() or request.user.username}!')
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
    """
    Displays a list of active job postings with search, filtering, and pagination.
    """
    jobs_list = Job.objects.filter(is_active=True).order_by('-date_posted')
    query, category, job_type = request.GET.get('q'), request.GET.get('category'), request.GET.get('job_type')

    if query:
        jobs_list = jobs_list.filter(
            models.Q(title__icontains=query) |
            models.Q(description__icontains=query) |
            models.Q(company_name__icontains=query) |
            models.Q(location__icontains=query)
        )
    if category:
        jobs_list = jobs_list.filter(category__name__iexact=category)
    if job_type:
        jobs_list = jobs_list.filter(job_type__iexact=job_type)

    sort_by = request.GET.get('sort_by', 'newest')
    
    if sort_by == 'oldest':
        jobs_list.order_by('date_posted')
    else: 
        jobs_list.order_by('-date_posted')

    now = timezone.now()
    for job in jobs_list:
        time_since_posted = now - job.date_posted
        job.is_hot_job = time_since_posted < timedelta(hours=24)

    paginator = Paginator(jobs_list, 8)
    page_number = request.GET.get('page')
    try:
        jobs = paginator.page(page_number)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        jobs = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        jobs = paginator.page(paginator.num_pages)

    context = {
        'jobs': jobs,
        'categories': Category.objects.all(),
        'job_types': [jt[0] for jt in Job.JOB_TYPE_CHOICES],
        'current_query': query or '',
        'current_category': category or '',
        'current_job_type': job_type or '',
        'current_sort_by': sort_by,
    }
    return render(request, 'job_list.html', context)


def job_detail_view(request, slug):
    job = get_object_or_404(Job, slug=slug)
    has_applied = False
    is_saved = False

    application_form = None
    if job.application_method == 'Internal':
        application_form = InternalApplicationForm()

    now = timezone.now()
    time_since_posted = now - job.date_posted
    job.is_hot_job = time_since_posted < timedelta(hours=24)

    if request.user.is_authenticated and request.user.is_applicant:
        if job.application_method == 'Internal':
            has_applied = Application.objects.filter(applicant=request.user, job=job).exists()
        
        is_saved = SavedJob.objects.filter(user=request.user, job=job).exists()

    related_jobs = []
    if job.category:
        related_jobs = Job.objects.filter(
            category=job.category
        ).exclude(slug=job.slug).order_by('-date_posted')[:3] 

    context = {
        'job': job,
        'has_applied': has_applied,
        'is_saved': is_saved,
        'related_jobs': related_jobs,
        'application_form': application_form,
    }

    return render(request, 'job_detail.html', context)


@login_required
@applicant_required
@require_http_methods(["GET", "POST"]) 
def job_apply_view(request, slug):
    print(f"DEBUG: Searching for job with slug: '{slug}'") 
    job = Job.objects.filter(slug__iexact=slug.strip()).first()

    if job.application_method == 'Email':
        messages.info(request, "Please follow the email instructions in the job description.")
        return redirect('job_detail', slug=job.slug)

    # --- EXTERNAL METHOD ---
    if job.application_method == 'External':
        if not job.external_application_url:
            messages.error(request, 'This job does not have an external application link configured.')
            return redirect('job_detail', slug=job.slug)
    
        application_exists = Application.objects.filter(applicant=request.user, job=job).exists()
        
        url = job.external_application_url.strip()

        if not url:
            return HttpResponseBadRequest("Invalid external application URL")

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        if not application_exists:
            try:
                Application.objects.create(
                    applicant=request.user, 
                    job=job, 
                    status='Clicked Apply Link'
                )
            except IntegrityError:
                pass
        return HttpResponseRedirect(url)

    # --- INTERNAL METHOD ---
    elif job.application_method == 'Internal':
        if Application.objects.filter(applicant=request.user, job=job).exists():
            messages.info(request, f'You have already submitted an application for "{job.title}".')
            return redirect('job_detail', slug=job.slug)

        if request.method == 'POST':
            form = InternalApplicationForm(request.POST, request.FILES)
            if form.is_valid():
                application = form.save(commit=False)
                application.applicant = request.user
                application.job = job
                application.status = 'Submitted'
                
                try:
                    application.save()
                    messages.success(request, f'Successfully submitted your application for "{job.title}"!')
                    return redirect('applicant_applications_list')
                except IntegrityError:
                    messages.error(request, 'You have already submitted an application for this job.')
                    return redirect('job_detail', slug=job.slug)
            else:
                messages.error(request, 'Please correct the errors in the application form.')
                return redirect('job_detail', slug=job.slug) 
        
        else: 
            messages.info(request, 'Please complete the form below to apply.')
            return redirect('job_detail', slug=job.slug)

    else:
        messages.error(request, 'Invalid application method configured for this job.')
        return redirect('job_detail', slug=job.slug)


# ----------------------------
# Applicant Views
# ----------------------------

@applicant_required
def applicant_dashboard(request):
    apps = Application.objects.filter(applicant=request.user)
    saved_jobs = SavedJob.objects.filter(user=request.user).select_related('job').order_by('-saved_at')
    
    # Fetch the most recent successful subscription
    subscription = JobSubscription.objects.filter(
        user=request.user, 
        status='success'
    ).order_by('-expiry_date').first()

    days_left = 0
    if subscription and subscription.expiry_date:
        if subscription.expiry_date > timezone.now():
            diff = subscription.expiry_date - timezone.now()
            days_left = diff.days + 1 
        else:
            days_left = 0

    context = {
        'total_applied': apps.count(),
        'recent_applications': apps.order_by('-application_date')[:5],
        'saved_jobs': saved_jobs,
        'subscription': subscription,
        'days_left': days_left,
    }
    return render(request, 'applicants/dashboard.html', context)

@applicant_required
def applicant_applications_list(request):
    """
    Displays a detailed list of all applications submitted by the current applicant.
    """
    all_applications = Application.objects.filter(applicant=request.user).select_related('job').order_by('-application_date')
    
    context = {
        'all_applications': all_applications,
    }
    return render(request, 'applicants/applications_list.html', context)


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
    if request.GET.get('export') == 'subscriptions':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="job_subscriptions.csv"'
        writer = csv.writer(response)
        writer.writerow(['Full Name', 'Email', 'Plan', 'Date Subscribed', 'Amount', 'WhatsApp', 'Category'])
        
        subs = JobSubscription.objects.filter(status='success').select_related('user')
        for s in subs:
            writer.writerow([
                s.user.get_full_name() or s.user.username,
                s.user.email,
                s.plan_type,
                s.created_at.strftime('%Y-%m-%d'),
                s.amount,
                s.whatsapp_number,
                s.interest_category
            ])
        return response

    recent_jobs_with_apps = Job.objects.filter(is_active=True).annotate(
        app_count=models.Count('applications')
    ).order_by('-date_posted')
    
    job_app_page_number = request.GET.get('job_app_page', 1)
    paginator = Paginator(recent_jobs_with_apps, 10) 
    try:
        job_app_page_obj = paginator.page(job_app_page_number)
    except Exception:
        job_app_page_obj = paginator.page(paginator.num_pages)

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        subscribers_context = get_subscribers_context(request)
        return render(request, 'staff/subscribers_table.html', subscribers_context)
     
    job_subscriptions = JobSubscription.objects.filter(status='success').select_related('user').order_by('-created_at')
    
    sub_query = request.GET.get('sub_q')
    if sub_query:
        job_subscriptions = job_subscriptions.filter(
            models.Q(user__email__icontains=sub_query) | 
            models.Q(user__first_name__icontains=sub_query) |
            models.Q(user__last_name__icontains=sub_query)
        )

    # Pagination: 10 subscriptions per page
    sub_page_number = request.GET.get('sub_page', 1)
    sub_paginator = Paginator(job_subscriptions, 10)
    
    try:
        sub_page_obj = sub_paginator.page(sub_page_number)
    except Exception:
        sub_page_obj = sub_paginator.page(1)

    context = {
        'total_jobs': Job.objects.count(),
        'total_applicants': CustomUser.objects.filter(is_applicant=True).count(),
        'applications': Application.objects.count(),
        'verified_users': CustomUser.objects.filter(is_active=True, is_staff=False, is_moderator=False).count(),
        'recent_jobs_with_apps': job_app_page_obj.object_list,
        'job_app_page_obj': job_app_page_obj,
        'job_subscriptions': sub_page_obj.object_list,
        'sub_page_obj': sub_page_obj,
        'sub_query': sub_query
    }

    recent_jobs = Job.objects.select_related('posted_by').order_by('-date_posted')[:5]
    recent_applicants = CustomUser.objects.order_by('-date_joined')[:5]
    recent_applications = Application.objects.select_related('applicant', 'job').order_by('-application_date')[:5]
    
    activity_list = []
    for job in recent_jobs:
        activity_list.append({'timestamp': job.date_posted, 'type': 'job_created', 'message': f'Job "{job.title}" created by {job.posted_by.username}.'})
    for applicant in recent_applicants:
        activity_list.append({'timestamp': applicant.date_joined, 'type': 'applicant_registered', 'message': f'Applicant "{applicant.get_full_name() or applicant.username}" registered.'})
    for app in recent_applications:
        activity_list.append({'timestamp': app.application_date, 'type': 'job_applied', 'message': f'Applicant "{app.applicant.get_full_name() or app.applicant.username}" clicked apply for "{app.job.title}".'})
    
    activity_list.sort(key=lambda x: x['timestamp'], reverse=True)
    context['recent_activity_log'] = activity_list[:15]

    if request.user.is_staff:
        context.update(get_subscribers_context(request))

    return render(request, 'moderator/dashboard.html', context)


@moderator_required
def job_list_create(request):
    form = JobForm(request.POST or None)
    query = request.GET.get('q', '')
    if query:
        jobs_list = Job.objects.filter(
            Q(title__icontains=query) |
            Q(company_name__icontains=query) |
            Q(description__icontains=query)
        ).order_by('-date_posted')
    else:
        jobs_list = Job.objects.all().order_by('-date_posted')
    paginator = Paginator(jobs_list, 10)
    page = request.GET.get('page')

    try:
        jobs = paginator.page(page)
    except PageNotAnInteger:
        jobs = paginator.page(1)
    except EmptyPage:
        jobs = paginator.page(paginator.num_pages)
    if request.method == 'POST' and form.is_valid():
        job = form.save(commit=False)
        job.posted_by = request.user
        job.save()
        messages.success(request, f'Job "{job.title}" created successfully!')
        return redirect('job_list_create')

    context = {
        'form': form,
        'jobs': jobs, 
        'query': query, 
    }
    return render(request, 'moderator/job_list_create.html', context)


@moderator_required
def job_update_delete(request, slug):
    job = get_object_or_404(Job, slug=slug)
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

    # Retrieve raw signup data, converting TruncDay to DateField
    signups_raw = CustomUser.objects.filter(is_applicant=True).annotate(
        date=Cast(TruncDay('date_joined'), output_field=DateField())
    ).values('date').annotate(count=models.Count('id')).order_by('date')

    if signups_raw:
        start_date = signups_raw.first()['date']
        end_date = signups_raw.last()['date']
    else:
        start_date = date.today()
        end_date = date.today()

    signups_dict = {str(item['date']): item['count'] for item in signups_raw}

    # Generate continuous date list
    continuous_signups_data = []
    current_date = start_date
    while current_date <= end_date:
        continuous_signups_data.append({
            'date': current_date.isoformat(),
            'count': signups_dict.get(str(current_date), 0)
        })
        current_date += timedelta(days=1)

    # Chart 2: Jobs by Category
    jobs_by_category = Category.objects.annotate(
        job_count=models.Count('jobs')
    ).values('name', 'job_count').order_by('-job_count')

    # Chart 3: Top Jobs by Application Clicks
    top_jobs_applied = Job.objects.annotate(
        application_count=models.Count('applications')
    ).values('title', 'application_count').order_by('-application_count')[:5]

    # Debugging data
    applicant_details = CustomUser.objects.filter(is_applicant=True).values(
        'first_name', 'last_name', 'date_joined'
    ).order_by('date_joined')

    context = {
        'signups_data_json': mark_safe(json.dumps(continuous_signups_data)),
        'jobs_by_category_json': mark_safe(json.dumps(list(jobs_by_category))), 
        'top_jobs_applied_json': mark_safe(json.dumps(list(top_jobs_applied))), 
        'applicant_details': list(applicant_details),
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
        return redirect('manage_moderators')
    return render(request, 'staff/is_staff_create_moderator.html', {'form': form})


@staff_required
def manage_moderators(request, user_id=None):
    moderators_list = User.objects.filter(is_moderator=True).order_by('username')

    search_query = request.GET.get('q')
    if search_query:
        moderators_list = moderators_list.filter(
            Q(username__icontains=search_query) | Q(email__icontains=search_query)
        )
        
    # --- Pagination Logic ---
    paginator = Paginator(moderators_list, 10) # Show 10 moderators per page
    page_number = request.GET.get('page', 1)
    
    try:
        page_obj = paginator.page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)
        
    editing_user = None
    edit_form = None

    if user_id:
        try:
            editing_user = get_object_or_404(User, id=user_id, is_moderator=True)
        except Http404:
            messages.error(request, 'Moderator not found.')
            return redirect('manage_moderators')
    
    # --- HANDLE POST REQUESTS (Update, Delete) ---
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'delete':
            if editing_user:
                editing_user.is_staff = False
                editing_user.save()
                messages.success(request, f'Moderator "{editing_user.username}" has been demoted successfully.')
            return redirect('manage_moderators')
        
        elif action == 'update':
            if editing_user:
                edit_form = ModeratorUpdateForm(request.POST, instance=editing_user)
                if edit_form.is_valid():
                    edit_form.save()
                    messages.success(request, f'Moderator "{editing_user.username}" updated successfully.')
                    return redirect('manage_moderators')
                else:
                    messages.error(request, 'Error updating moderator. Please check the form.')
    
    # --- HANDLE GET REQUESTS (Pre-populate Edit Form) ---
    if editing_user and not edit_form:
        edit_form = ModeratorUpdateForm(instance=editing_user)

    context = {
        'page_obj': page_obj,
        'search_query': search_query,
        'editing_user': editing_user,
        'edit_form': edit_form,
    }

    return render(request, 'staff/manage_moderators.html', context)


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
def category_update_delete(request, slug):
    category = get_object_or_404(Category, slug=slug)
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
                return redirect('category_update_delete', slug=category.slug)
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
            'category name', 'application method', 'external application url',
            'description', 'is active', 'job expiry date'
        ]
        header_map = {
            'title': 'title',
            'company name': 'company_name',
            'location': 'location',
            'job type': 'job_type',
            'category name': 'category',
            'application method': 'application_method',
            'external application url': 'external_application_url',
            'description': 'description',
            'is active': 'is_active',
            'job expiry date': 'job_expiry_date',
        }
        job_type_choices = [choice[0].lower() for choice in Job.JOB_TYPE_CHOICES]

        application_method_choices = [choice[0].lower() for choice in Job.APPLICATION_METHOD_CHOICES]

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

            if not any(row):
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

                elif model_field == 'job_expiry_date':
                    if value:
                        try:
                            job_data['job_expiry_date'] = datetime.strptime(value, '%d/%m/%Y').date()
                        except ValueError:
                            try:
                                job_data['job_expiry_date'] = datetime.strptime(value, '%Y-%m-%d').date()
                            except ValueError:
                                row_errors.append(
                                    f"Row {i+1}: Invalid date format for '{csv_col}'. "
                                    f"Expected 'YYYY-MM-DD' or 'DD/MM/YYYY', got '{value}'."
                                )
                    else:
                        job_data['job_expiry_date'] = None
                
                elif model_field == 'application_method': 
                    if value and value.lower() in application_method_choices:
                        job_data['application_method'] = value
                    elif value:
                        row_errors.append(
                            f"Row {i+1}: Invalid application method '{value}'. Must be one of: "
                            f"{', '.join(application_method_choices)}"
                        )
                    else:
                        url = row_data.get('external application url', '').strip()
                        job_data['application_method'] = 'External' if url else 'Internal'

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
                        'application_method': job_data['application_method'],
                        'external_application_url': job_data['external_application_url'],
                        'description': job_data['description'],
                        'is_active': job_data['is_active'],
                        'job_expiry_date': job_data['job_expiry_date'],
                        'posted_by': request.user,
                    }
                )
                if created:
                    jobs_created += 1
                else:
                    jobs_updated += 1
            except Exception as e:
                errors.append(f"Row {i+1}: Failed to save job '{job_data.get('title')}' - {e}")

        if errors:
            for e in errors[:10]:
                messages.error(request, e)
            if len(errors) > 10:
                messages.warning(request, f"And {len(errors) - 10} more errors hidden. Please check the file carefully.")
            messages.warning(request, f"Processed {jobs_processed} rows with {len(errors)} error(s). {jobs_created} created, {jobs_updated} updated.")
        else:
            messages.success(request, f"CSV upload successful! {jobs_created} jobs created, {jobs_updated} jobs updated.")

        return redirect('job_list_create')

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
    headers = [
        'Title', 'Company Name', 'Location', 'Job Type',
        'Category Name', 'Application Method', 'External Application URL', 'Description', 'Is Active',
        'Job Expiry Date'
    ]
    writer.writerow(headers)

    writer.writerow([
        'Software Engineer', 'Acme Corp', 'Remote', 'Full-time',
        'Technology', 'https://acmecorp.com/careers/software-engineer',
        'Develop and maintain software applications.', 'True', '2025-12-31'
    ])
    writer.writerow([
        'Marketing Specialist', 'Global Brands', 'New York, NY', 'Full-time',
        'Marketing', 'Internal', '',
        'Execute marketing campaigns and analyze performance.', 'True', '17/09/2025'
    ])
    writer.writerow([
        'Customer Support Intern', 'Startup Innovations', 'San Francisco, CA', 'Internship',
        'Customer Service', '',
        'Assist customers with product inquiries and support.', 'False', ''
    ])

    return response


@applicant_required
def manage_job_alerts(request, alert_id=None):
    alert = None
    if alert_id:
        alert = get_object_or_404(JobAlert, pk=alert_id, user=request.user)
        form = JobAlertForm(request.POST or None, instance=alert)
    else:
        form = JobAlertForm(request.POST or None)

    if request.method == 'POST':
        if 'delete_alert' in request.POST and alert:
            alert_name = alert.alert_name
            alert.delete()
            messages.success(request, f'Job alert "{alert_name}" deleted successfully.')
            return redirect('manage_job_alerts')
        elif form.is_valid():
            try:
                job_alert = form.save(commit=False)
                job_alert.user = request.user

                if not alert_id:
                    job_alert.last_sent = timezone.now()

                job_alert.save()
                form.save_m2m()
                if alert_id:
                    messages.success(request, f'Job alert "{job_alert.alert_name}" updated successfully!')
                else:
                    messages.success(request, f'Job alert "{job_alert.alert_name}" created successfully!')
                return redirect('manage_job_alerts')
            except IntegrityError:
                messages.error(request, 'You already have an alert with this name.')
            except Exception as e:
                messages.error(request, f'An error occurred: {e}')
    
    job_alerts = JobAlert.objects.filter(user=request.user).order_by('-created_at')
    context = {
        'form': form,
        'job_alerts': job_alerts,
        'editing_alert': alert is not None,
    }
    return render(request, 'applicants/job_alerts.html', context)


@login_required
@applicant_required
def save_job(request, slug):
    job = get_object_or_404(Job, slug=slug)
    try:
        SavedJob.objects.create(user=request.user, job=job)
        messages.success(request, f'Job "{job.title}" saved successfully!')
    except IntegrityError:
        messages.info(request, f'Job "{job.title}" is already in your saved list.')
    return redirect('job_detail', slug=job.slug)

@login_required
@applicant_required
def unsave_job(request, slug):
    job = get_object_or_404(Job, slug=slug)
    saved_job = SavedJob.objects.filter(user=request.user, job=job)
    if saved_job.exists():
        saved_job.delete()
        messages.success(request, f'Job "{job.title}" removed from your saved list.')
    else:
        messages.info(request, f'Job "{job.title}" was not found in your saved list.')
    return redirect('job_detail', slug=job.slug)


@moderator_required
def job_bulk_delete(request):
    if request.method == 'POST':
        job_ids = request.POST.getlist('job_ids')

        if job_ids:
            deleted_count, _ = Job.objects.filter(id__in=job_ids).delete()
            messages.success(request, f"{deleted_count} job(s) have been successfully deleted.")
        else:
            messages.warning(request, "No jobs were selected for deletion.")
    return redirect('job_list_create')


def submit_resume_view(request):
    if request.method == 'POST':
        form = ResumeUploadForm(request.POST, request.FILES)
        if form.is_valid():
            full_name = form.cleaned_data['full_name']
            applicant_email = form.cleaned_data['email']
            resume_file = form.cleaned_data.get('resume')
            request_template = form.cleaned_data.get('request_template')

            success_messages = []

            if resume_file:
                if not resume_file.content_type in ['application/pdf', 'application/msword', 
                                                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                    messages.error(request, 'Invalid file type. Please upload a PDF or Word document.')
                    return redirect('submit_resume')

                if resume_file.size > 5 * 1024 * 1024:  # 5 MB limit
                    messages.error(request, 'File size exceeds 5MB limit.')
                    return redirect('submit_resume')

                staff_emails = User.objects.filter(is_staff=True).values_list('email', flat=True)
                staff_emails = [email for email in staff_emails if email]

                if staff_emails:
                    resume_content = resume_file.read()
                    resume_file.seek(0)

                    attachments = [(resume_file.name, resume_content, resume_file.content_type)]

                    email_context = {'full_name': full_name, 'email': applicant_email, 'file_name': resume_file.name}

                    try:
                        send_templated_email(
                            'emails/staff_resume_notification.html',
                            'New Resume Submission for Review',
                            staff_emails,
                            email_context,
                            attachments=attachments
                        )
                        success_messages.append('Your resume has been submitted for review.')
                    except Exception as e:
                        messages.error(request, f'Failed to send email: {e}')
                        return redirect('submit_resume')
                else:
                    messages.error(request, 'Submission failed: No staff email addresses found.')

            if request_template:
                template_link = request.build_absolute_uri(static('resume_template/Resume-Template.docx'))
                template_context = {'full_name': full_name, 'template_link': template_link}

                try:
                    send_templated_email(
                        'emails/applicant_template_link.html',
                        'Your Resume Template from Remote Ready With Tess(RRWT)',
                        [applicant_email],
                        template_context
                    )
                    success_messages.append('A link to a resume template has been sent to your email.')
                except Exception as e:
                    messages.error(request, f'Failed to send template email: {e}')
                    return redirect('submit_resume')

            if not resume_file and not request_template:
                messages.error(request, 'Please either upload a resume or check the box to request a template.')
                return redirect('submit_resume')

            for msg in success_messages:
                messages.success(request, msg)
            return redirect('submit_resume')

    else:
        form = ResumeUploadForm()

    return render(request, 'submit_resume.html', {'form': form})


# -------------------------------
# View for Recruiter Registration
# -------------------------------

@require_http_methods(["GET", "POST"])
def recruiter_register(request):
    """
    Handles recruiter registration: creates a user (is_moderator=True), 
    recruiter profile, and sends an account activation email.
    """
    if request.method == 'POST':
        form = RecruiterRegistrationForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    recruiter = form.save()  
                    user = recruiter.user   

                current_site = get_current_site(request)
                context = {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                }

                try:
                    email_sent = send_templated_email(
                        template_name='emails/recruiter_activation_email.html',
                        subject='Activate your Account',
                        recipient_list=[user.email],
                        context=context
                    )
                except Exception as e:
                    email_sent = False

                if email_sent:
                    messages.success(
                        request,
                        'Your account has been created! Please check your email to activate your account.'
                    )
                else:
                    messages.warning(
                        request,
                        'Your account has been created, but we could not send the verification email. Please contact support.'
                    )

                return redirect('login')

            except Exception as e:
                messages.error(request, f"An error occurred during registration: {str(e)}")
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = RecruiterRegistrationForm()

    return render(request, 'post_job.html', {'form': form})


@require_http_methods(["GET"])
def activate_account(request, uidb64, token):
    CustomUser = User
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user = None

    if user is not None:
        if user.is_active:
            messages.info(request, 'Your account is already activated. Please log in.')
            return redirect('login')

        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()

            messages.success(
                request,
                'Thank you for confirming your email. Your account has been activated successfully!'
            )
            return redirect('login')
        else:
            messages.error(request, 'Activation link is invalid or has expired!')
            return redirect('post_job')
    else:
        messages.error(request, 'Invalid activation request!')
        return redirect('post_job')
    

# -------------------------------
# Blog Post Views
# -------------------------------

def post_list_view(request):
    """
    View to display blog posts. 
    Staff see all posts (including scheduled), 
    while the public only sees published posts.
    """
    query = request.GET.get('q')
    posts_list = Post.objects.all()

    # 2. If the user is NOT staff, filter out the future/scheduled posts
    if not request.user.is_staff:
        posts_list = posts_list.filter(publish_date__lte=timezone.now())

    # 3. Apply search query if it exists
    if query:
        posts_list = posts_list.filter(
            Q(title__icontains=query) |
            Q(content__icontains=query)
        ).distinct()
    
    # 4. Order by date (Scheduled posts will appear at the top if they are future-dated)
    posts_list = posts_list.order_by('-publish_date')

    # Pagination logic
    paginator = Paginator(posts_list, 6) 
    page_number = request.GET.get('page')
    try:
        page_obj = paginator.get_page(page_number)
    except (PageNotAnInteger, EmptyPage):
        page_obj = paginator.get_page(1)
    
    context = {
        'page_obj': page_obj,
        'query': query,
    }
    return render(request, 'blog/post_list.html', context)


def post_detail_view(request, slug):
    """
    View to display a single blog post and its comments.
    Staff can preview scheduled posts, but regular users cannot.
    """
    # 1. Fetch the post
    post = get_object_or_404(Post, slug=slug)

    # 2. Security Check: If the post is scheduled for the future and user isn't staff, hide it
    if post.publish_date > timezone.now() and not request.user.is_staff:
        from django.http import Http404
        raise Http404("This post is scheduled for a later date.")

    comments = post.comments.all()

    has_commented = False
    if request.user.is_authenticated:
        if Comment.objects.filter(post=post, author=request.user).exists():
            has_commented = True

    comment_form = CommentForm()

    # 3. Filter Related Posts so only currently 'live' posts appear
    live_posts = Post.objects.filter(publish_date__lte=timezone.now())

    if post.category:
        related_posts = live_posts.filter(
            category=post.category  
        ).exclude(pk=post.pk).order_by('-publish_date')[:3] 
    else:
        related_posts = live_posts.exclude(pk=post.pk).order_by('-publish_date')[:3]

    return render(request, 'blog/post_detail.html', {
        'post': post,
        'comments': comments,
        'comment_form': comment_form,
        'has_commented': has_commented,
        'related_posts': related_posts,
    })


@staff_required
def post_create_view(request):
    """
    View for creating a new blog post. Requires staff access.
    """
    if request.method == 'POST':
        form = PostForm(request.POST, request.FILES)
        if form.is_valid():
            post = form.save(commit=False)
            post.author = request.user
            post.save()
            return redirect('blog_detail', slug=post.slug)
    else:
        form = PostForm()
    
    return render(request, 'blog/post_form.html', {'form': form})

@staff_required
def post_update_view(request, slug):
    """
    View for updating an existing blog post. Requires staff access and ownership.
    """
    post = get_object_or_404(Post, slug=slug)
    if request.user != post.author:
        return redirect('blog_detail', slug=post.slug)

    if request.method == 'POST':
        form = PostForm(request.POST, request.FILES, instance=post)
        if form.is_valid():
            post = form.save()
            return redirect('blog_detail', slug=post.slug)
    else:
        form = PostForm(instance=post)
    
    return render(request, 'blog/post_form.html', {'form': form, 'post': post})

@staff_required
def post_delete_view(request, slug):
    """
    View for deleting a blog post. Requires staff access and ownership.
    """
    post = get_object_or_404(Post, slug=slug)
    if request.user != post.author:
        return redirect('blog_detail', slug=post.slug)
    
    if request.method == 'POST':
        post.delete()
        return redirect('blog_list')
    
    return render(request, 'blog/post_confirm_delete.html', {'post': post})


# -------------------------------
# Comment Views 
# -------------------------------

def add_comment_to_post(request, slug):
    """
    View to handle adding comments to a blog post. Requires applicant access.
    """
    post = get_object_or_404(Post, slug=slug, publish_date__lte=now())

    if Comment.objects.filter(post=post, author=request.user).exists():
        return redirect('blog_detail', slug=post.slug)

    if request.method == 'POST':
        form = CommentForm(request.POST)
        if form.is_valid():
            comment = form.save(commit=False)
            comment.post = post
            comment.author = request.user
            comment.save()
            return redirect('blog_detail', slug=post.slug)
            
    return redirect('blog_detail', slug=post.slug)


@csrf_exempt
def create_category(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            category_name = data.get('name')

            if category_name:
                category, created = BlogCategory.objects.get_or_create(name=category_name)
                if created:
                    return JsonResponse({'status': 'success', 'id': category.id, 'name': category.name})
                else:
                    return JsonResponse({'status': 'error', 'error': 'Category already exists.'}, status=409)
            else:
                return JsonResponse({'status': 'error', 'error': 'Category name is required.'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'error': 'Invalid JSON.'}, status=400)
    
    return JsonResponse({'status': 'error', 'error': 'Invalid request method.'}, status=405)


# -------------------------------------------------
# --- RENDER THE ANALYZER PAGE ---
# -------------------------------------------------

@login_required
def resume_analyzer_view(request: HttpRequest, job_slug: str) -> HttpResponse:
    """
    Checks for user profile and resume status. Passes flags to the template
    to conditionally show upload form, processing message, or analysis results.
    """
    if not request.user.is_applicant:
        messages.error(request, "This feature is for applicants only.")
        return redirect('job_list')

    job = get_object_or_404(Job, slug=job_slug, is_active=True)

    needs_upload = False
    is_processing = False
    profile = None

    try:
        profile = request.user.applicant_profile

        if not profile.resume:
            needs_upload = True
            messages.info(request, "Please upload your resume to start the analysis.")

        elif profile.resume and not profile.resume_text:
            is_processing = True
            extracted = extract_resume_text(profile.resume.path)
            if extracted:
                profile.resume_text = extracted
                profile.save()
                is_processing = False
                messages.success(request, "Your resume has been processed successfully.")
            else:
                messages.warning(request, "We couldn't extract text from your resume. Try re-uploading a clearer file.")

    except ApplicantProfile.DoesNotExist:
        messages.warning(request, "Applicant profile not found. Please upload your resume to create one.")
        needs_upload = True
        return redirect('job_list')
    except Exception as e:
        messages.error(request, f"Unexpected error while accessing your profile: {e}")
        print(f"ERROR accessing profile for user {request.user.id}: {e}")
        return redirect('job_list')

    context = {
        'job': job,
        'needs_upload': needs_upload,
        'is_processing': is_processing,
        'profile': profile
    }
    return render(request, 'resume_analyzer.html', context)


# -------------------------------------------------
# --- HANDLE RESUME UPLOAD ---
# -------------------------------------------------

@login_required
def handle_resume_upload_view(request: HttpRequest, job_slug: str) -> HttpResponse:
    """
    Handles resume file upload and automatically extracts text upon upload.
    """
    if not request.user.is_applicant:
        messages.error(request, "Only applicants can upload resumes.")
        return redirect('job_list')

    job = get_object_or_404(Job, slug=job_slug)

    if request.method == 'POST':
        resume_file = request.FILES.get('resume_file')
        if not resume_file:
            messages.error(request, "No resume file was selected.")
            return redirect('resume_analyzer', job_slug=job.slug)

        allowed_types = [
            'application/pdf',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/msword'
        ]
        if resume_file.content_type not in allowed_types:
            messages.error(request, "Invalid file type. Please upload PDF or DOCX.")
            return redirect('resume_analyzer', job_slug=job.slug)

        if resume_file.size > 5 * 1024 * 1024:
            messages.error(request, "File size exceeds 5MB limit.")
            return redirect('resume_analyzer', job_slug=job.slug)

        try:
            profile, _ = ApplicantProfile.objects.get_or_create(user=request.user)

            # Delete old resume if exists
            if profile.resume and default_storage.exists(profile.resume.name):
                default_storage.delete(profile.resume.name)

            profile.resume = resume_file
            profile.resume_text = ""
            profile.save()

            extracted = extract_resume_text(profile.resume.path)
            if extracted:
                profile.resume_text = extracted
                profile.save()
                messages.success(request, f"Resume '{resume_file.name}' uploaded and processed successfully.")
            else:
                messages.warning(request, f"Resume '{resume_file.name}' uploaded, but text extraction failed. Try re-uploading.")

            return redirect('resume_analyzer', job_slug=job.slug)

        except Exception as e:
            messages.error(request, f"Error during upload: {e}")
            return redirect('resume_analyzer', job_slug=job.slug)

    return redirect('resume_analyzer', job_slug=job.slug)


# -------------------------------------------------
# --- AI ANALYSIS API ENDPOINT ---
# -------------------------------------------------

MAX_RETRIES = 5
INITIAL_BACKOFF_DELAY = 4

@login_required
def run_analysis_api_view(request: HttpRequest, job_slug: str) -> JsonResponse:
    """
    Calls Gemini API to analyze the applicant’s resume vs job description with 
    retry logic for rate limiting (HTTP 429).
    """
    if not request.user.is_applicant:
        return JsonResponse({"error": "This feature is for applicants only."}, status=403)

    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method. Please use POST."}, status=405)

    try:
        job = get_object_or_404(Job, slug=job_slug)
        profile = request.user.applicant_profile 

        if not profile.resume_text:
            return JsonResponse({"error": "Resume text not found. Please upload or re-process your resume."}, status=404)

        resume_text = profile.resume_text
        job_description = strip_tags(job.description)

        # AI system + user prompts (Defined once)
        system_prompt = (
            "You are an expert AI recruitment assistant specialized in the Nigerian job market. "
            "Analyze the candidate's resume against the job description and respond in JSON with keys: "
            "'score' (0-100), 'summary', 'pros', and 'cons'."
        )

        user_query = f"""
        Candidate Resume:
        --- START ---
        {resume_text}
        --- END ---

        Job Description:
        --- START ---
        {job_description}
        --- END ---

        Provide the JSON analysis based on resume-job alignment.
        """

        payload = {
            "contents": [{"parts": [{"text": user_query}]}],
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.5,
                "responseSchema": {
                    "type": "OBJECT",
                    "properties": {
                        "score": {"type": "INTEGER"},
                        "summary": {"type": "STRING"},
                        "pros": {"type": "ARRAY", "items": {"type": "STRING"}},
                        "cons": {"type": "ARRAY", "items": {"type": "STRING"}}
                    },
                    "required": ["score", "summary", "pros", "cons"]
                }
            }
        }

        apiKey = config("GEMINI_API_KEY")
        model_name = "gemini-2.5-flash-preview-09-2025"
        apiUrl = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={apiKey}"
        
        # Initialize response before the loop
        response = None 

        # --- Implementation of Retry Loop with Exponential Backoff ---
        for attempt in range(MAX_RETRIES):
            try:
                # 1. Attempt the API call
                response = requests.post(
                    apiUrl, 
                    headers={'Content-Type': 'application/json'}, 
                    data=json.dumps(payload), 
                    timeout=60
                )
                
                # 2. Check for 429 specifically before raising other errors
                if response.status_code == 429:
                    raise HTTPError("Rate Limit Exceeded (429)")

                # 3. Raise an exception for other bad status codes (4xx, 5xx)
                response.raise_for_status()
                
                # 4. If successful, break the loop and proceed to processing logic
                break 

            except HTTPError as e:
                if response is not None and response.status_code == 429 and attempt < MAX_RETRIES - 1:
                    wait_time = INITIAL_BACKOFF_DELAY * (2 ** attempt) + (time.time() * 0.1) % 1
                    print(f"Rate limit hit. Retrying in {wait_time:.2f} seconds (Attempt {attempt + 1}/{MAX_RETRIES})")
                    time.sleep(wait_time)
                    continue 
                else:
                    print(f"Final API call failed after {attempt + 1} attempts: {e}")
                    status_code = response.status_code if response is not None else 500
                    return JsonResponse({
                        "error": f"AI service failed to respond: {status_code} {getattr(response, 'reason', 'Unknown Reason')}"
                    }, status=status_code)
            
            except RequestException as e:
                if attempt < MAX_RETRIES - 1:
                    wait_time = INITIAL_BACKOFF_DELAY * (2 ** attempt)
                    print(f"Network error: {e}. Retrying in {wait_time:.2f} seconds (Attempt {attempt + 1}/{MAX_RETRIES})")
                    time.sleep(wait_time)
                    continue
                else:
                    print(f"Final network failure after {attempt + 1} attempts: {e}")
                    return JsonResponse({"error": "Failed to connect to the AI service after multiple retries. Try refreshing the page."}, status=503)
        
        else:
             return JsonResponse({"error": "AI service rate limit exceeded after all retries. Please try again later."}, status=429)
        # --- End of Retry Loop ---
        
        try:
            result = response.json()
        except json.JSONDecodeError:
            print(f"AI response was not valid JSON: {response.text}")
            return JsonResponse({"error": "AI service returned invalid data."}, status=500)


        if (
            result.get('candidates')
            and result['candidates'][0].get('content')
            and result['candidates'][0]['content'].get('parts')
        ):
            ai_part = result['candidates'][0]['content']['parts'][0]
            if 'text' not in ai_part:
                return JsonResponse({"error": "Unexpected AI response format (missing text part)."}, status=500)

            try:
                ai_data = json.loads(ai_part['text'])
            except json.JSONDecodeError:
                print(f"AI attempted to return data but it was corrupted: {ai_part.get('text', 'No text found')}")
                return JsonResponse({"error": "AI analysis data was corrupted (Invalid JSON structure)."}, status=500)

            if not all(k in ai_data for k in ["score", "summary", "pros", "cons"]):
                return JsonResponse({"error": "AI response missing required analysis keys."}, status=500)

            # --- Save the results to the profile (using appropriate update_fields) ---
            profile.parsed_summary = ai_data.get("summary", "")
            profile.parsed_skills = ai_data.get("pros", [])
            profile.parsed_experience = ai_data.get("cons", [])
            profile.save(update_fields=["parsed_summary", "parsed_skills", "parsed_experience"])

            return JsonResponse(ai_data, status=200)

        # If the outer structure of the AI response is bad
        return JsonResponse({"error": "Unexpected AI response structure (missing candidates)."}, status=500)
        
        # --- END: SUCCESSFUL RESPONSE PROCESSING ---

    except Exception as e:
        # Catch any remaining critical errors
        print(f"CRITICAL ERROR in run_analysis_api_view: {str(e)}")
        return JsonResponse({"error": f"An unexpected critical error occurred: {e}"}, status=500)

@login_required
def delete_account_view(request: HttpRequest) -> HttpResponse:
    """
    Handles the permanent deletion of a user's account.
    This view only accepts POST requests and checks for confirmation text.
    """
    if request.method != 'POST':
        return redirect('applicant_dashboard')

    user = request.user
    confirmation_text = request.POST.get('delete_confirm', '')
    if confirmation_text == 'delete':
        try:
            user_email = user.email
            user_username = user.username or user.first_name or user.email
            
            logout(request)
            
            user.delete()

            email_subject = "Your Account at Remote Ready With Tess has been Deleted"
            email_template = "emails/account_deleted.html"
            email_recipient_list = [user_email]
            email_context = {
                'username': user_username,
            }
            
            send_templated_email(
                email_template,
                email_subject,
                email_recipient_list,
                email_context
            )
            messages.success(request, f"The account for {user_email} has been permanently deleted.")
            return redirect('home')
            
        except Exception as e:
            messages.error(request, "An unexpected error occurred while deleting your account. Please contact support.")
            return redirect('home')
            
    else:
        messages.error(request, 'Confirmation text was incorrect. Your account has not been deleted.')
        return redirect('applicant_dashboard')
    


# ----------------------------
# Moderator Application Management Views
# ----------------------------

@moderator_required
def job_applications_moderator_list(request, job_slug):
    """
    Displays a list of all applications (Internal submissions and External clicks)
    for a specific job, allowing moderators to review and filter.
    """
    job = get_object_or_404(Job, slug=job_slug)
    applications_list = Application.objects.filter(job=job).select_related('applicant').order_by('-application_date')

    status_filter = request.GET.get('status')
    if status_filter and status_filter != 'All':
        applications_list = applications_list.filter(status=status_filter)

    query = request.GET.get('q')
    if query:
        applications_list = applications_list.filter(
            Q(applicant__username__icontains=query) |
            Q(applicant__email__icontains=query) |
            Q(cover_letter__icontains=query) |
            Q(full_name__icontains=query)
        )

    # Pagination
    paginator = Paginator(applications_list, 15)
    page_number = request.GET.get('page')
    try:
        applications = paginator.page(page_number)
    except PageNotAnInteger:
        applications = paginator.page(1)
    except EmptyPage:
        applications = paginator.page(paginator.num_pages)
        
    # Calculate counts for reporting/filters
    total_applications = Application.objects.filter(job=job).count()
    
    # Count of Internal submissions (where data is available)
    internal_submissions = Application.objects.filter(job=job, status='Submitted').count()
    
    # Calculate external clicks
    external_clicks = total_applications - internal_submissions

    context = {
        'job': job,
        'applications': applications,
        'total_applications': total_applications,
        'internal_submissions': internal_submissions,
        'external_clicks': external_clicks,
        'application_statuses': Application.STATUS_CHOICES,
        'current_status': status_filter,
        'query': query,
    }
    return render(request, 'moderator/job_applications_list.html', context)


@moderator_required
def application_status_update(request, pk):
    """
    API-like endpoint to quickly update the status of an application.
    Assumes an AJAX POST request.
    """
    application = get_object_or_404(Application, pk=pk)
    
    if request.method == 'POST':
        new_status = request.POST.get('status')
        valid_statuses = [choice[0] for choice in Application.STATUS_CHOICES]
        
        if new_status and new_status in valid_statuses:
            application.status = new_status
            application.save()
            messages.success(request, f'Status for application by {application.applicant.username} updated to "{new_status}".')
            return JsonResponse({'status': 'success', 'new_status': new_status})
        
        return JsonResponse({'status': 'error', 'message': 'Invalid status provided.'}, status=400)
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=405)


@moderator_required
def application_detail_view(request, pk):
    """
    Displays full details of a single application, 
    including internal form fields like salary, resume, etc.
    """
    application = get_object_or_404(
        Application.objects.select_related('job', 'applicant'),
        pk=pk
    )

    context = {
        'application': application,
        'is_internal_submission': (application.status == 'Submitted'),
        'application_statuses': Application.STATUS_CHOICES,
    }

    return render(request, 'moderator/application_detail.html', context)


@moderator_required
def application_resume_download(request, pk):
    """
    Securely downloads the applicant’s submitted resume.
    Only accessible to moderators/staff.
    """
    application = get_object_or_404(Application, pk=pk)

    if not application.submitted_resume:
        messages.error(request, "No resume file found for this application.")
        return redirect('application_detail_view', pk=pk)

    try:
        file_path = application.submitted_resume.path

        # Detect MIME type (PDF, DOCX, etc.)
        content_type, encoding = mimetypes.guess_type(file_path)
        content_type = content_type or "application/octet-stream"

        response = FileResponse(open(file_path, 'rb'), content_type=content_type)

        # Force download
        response['Content-Disposition'] = (
            f'attachment; filename="{application.submitted_resume.name}"'
        )

        return response

    except FileNotFoundError:
        messages.error(request, "The resume file could not be found on the server.")
        return redirect('application_detail_view', pk=pk)



@login_required
@applicant_required
def request_resume_template_view(request, job_slug: str) -> HttpResponse:
    """
    Sends a resume template Word document (.docx) to the applicant's email address
    using the centralized send_templated_email utility function.
    """
    if not request.user.is_applicant:
        messages.error(request, "This feature is for applicants only.")
        return redirect('job_list')
    
    job = get_object_or_404(Job, slug=job_slug, is_active=True)
    applicant_email = request.user.email
    
    template_dir = os.path.join(settings.BASE_DIR, 'static', 'resume_template')
    template_filename = 'Resume-Template.docx'
    template_path = os.path.join(template_dir, template_filename)
    
    if not os.path.exists(template_path):
        messages.error(request, "The resume template file is currently unavailable.")
        return redirect('resume_analyzer_view', job_slug=job_slug)
        
    try:
        with open(template_path, 'rb') as f:
            file_content = f.read()
        
        attachments = [
            (
                template_filename,
                file_content,
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            )
        ]
        
        email_context = {
            'user': request.user,
            'job': job,
            'company_name': 'Remote Ready Jobs', 
           
        }
        
        email_sent = send_templated_email(
            template_name='emails/resume_template_email.html',
            subject=f"Your Resume Template for the {job.title} Role",
            recipient_list=[applicant_email],
            context=email_context,
            attachments=attachments
        )
        
        if email_sent:
            messages.success(request, f"The resume template (Word Document) has been sent to your email: {applicant_email}")
        else:
            messages.error(request, "Failed to send the resume template email. Please check server logs.")

    except Exception as e:
        messages.error(request, f"An unexpected error occurred while preparing the email: {e}")
        # Log the error for debugging
        print(f"UNEXPECTED ERROR preparing resume template email for {applicant_email}: {e}")

    return redirect('job_detail', slug=job_slug)


@staff_required
def update_staff_bio(request):
    profile, created = StaffProfile.objects.get_or_create(user=request.user)
    
    if request.method == 'POST':
        form = StaffBioForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, "Your profile has been updated successfully.")
            return redirect(reverse('blog_list'))
    else:
        form = StaffBioForm(instance=profile)
    
    return render(request, 'blog/edit_staff_profile.html', {'form': form})


def privacy_policy(request):
    return render(request, 'privacy_policy.html')


PLANS = {
    '2_weeks': {'name': 'Intensive Search', 'price': 5000, 'days': 14, 'desc': 'Perfect for immediate needs.'},
    '1_month': {'name': 'Professional', 'price': 9000, 'days': 30, 'desc': 'Our most popular career booster.'},
    '3_months': {'name': 'Ultimate Career', 'price': 22000, 'days': 90, 'desc': 'Full long-term job support.'},
}

@login_required
def subscription_plans(request):
    return render(request, 'subscription/plans.html', {'plans': PLANS, 'paystack_public_key': settings.PAYSTACK_PUBLIC_KEY})


def render_success(request, sub):
    """
    Helper function to render the success page with subscription details.
    """
    plan_info = PLANS.get(sub.plan_type)
    context = {
        'user': sub.user,
        'plan_name': plan_info['name'],
        'amount': sub.amount,
        'expiry': sub.expiry_date,
        'reference': sub.reference,
        'whatsapp_number': sub.whatsapp_number,
        'interest_category': sub.interest_category,
    }
    return render(request, 'subscription/success.html', context)

def send_subscription_email(sub):
    """Helper function to handle the email logic once"""
    plan_info = PLANS.get(sub.plan_type)
    context = {
        'user': sub.user,
        'plan_name': plan_info['name'],
        'amount': sub.amount,
        'expiry': sub.expiry_date,
        'reference': sub.reference,
        'whatsapp_number': sub.whatsapp_number,
        'interest_category': sub.interest_category,
        'domain': getattr(settings, 'SITE_DOMAIN'),
        'protocol': 'https',
        'current_year': timezone.now().year
    }
    try:
        recipient_list = [str(sub.user.email)]
        send_templated_email(
            'emails/subscription_confirmed.html',
            'Your Subscription is Active!',
            recipient_list,
            context
        )
        sub.is_notified = True
        sub.save()
    except Exception as e:
        print(f"Email Error in verify_payment: {e}")

@login_required
def initialize_payment(request, plan_key):
    plan = PLANS.get(plan_key)
    
    if not plan:
        return JsonResponse({'status': 'error', 'message': 'Invalid plan'}, status=400)

    reference = str(uuid.uuid4())
    
    whatsapp = request.POST.get('whatsapp_number')
    interest = request.POST.get('interest_category')

    # 1. Create the local record (Keep status pending)
    sub = JobSubscription.objects.create(
        user=request.user,
        plan_type=plan_key,
        amount=plan['price'],
        reference=reference,
        whatsapp_number=whatsapp, 
        interest_category=interest,
        status='pending'
    )

    # 2. Paystack API Initialization
    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    
    callback_url = f"https://readyremotejob.com{reverse('verify_payment')}"

    data = {
        "email": request.user.email,
        "amount": int(plan['price'] * 100),
        "reference": reference,
        "callback_url": callback_url
    }
    
    try:
        r = requests.post(url, headers=headers, json=data, timeout=10)
        response = r.json()
        
        if response.get('status'):
            return JsonResponse({
                'status': 'success',
                'access_code': response['data']['access_code'],
                'reference': reference,
                'amount_kobo': int(plan['price'] * 100),
                'email': request.user.email
            })
            
    except Exception as e:
        print(f"Paystack Init Error: {e}")
        
    return JsonResponse({'status': 'error', 'message': 'Could not initialize payment'}, status=500)


def verify_payment(request):
    reference = request.GET.get('reference') or request.GET.get('trxref')
    if not reference:
        return render(request, 'subscription/failed.html', {'error': 'No reference provided.'})

    sub = get_object_or_404(JobSubscription, reference=reference)

    # 1. If Webhook already finished, just show success
    if sub.status == 'success':
        # Safety check: if webhook succeeded but email failed, try sending here
        if not sub.is_notified:
            send_subscription_email(sub)
        return render_success(request, sub)
    
    # 2. FALLBACK: If Webhook is slow, verify manually once
    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}
    
    try:
        r = requests.get(url, headers=headers, timeout=10)
        response = r.json()

        if response.get('status') and response['data']['status'] == 'success':
            plan_info = PLANS.get(sub.plan_type)
            
            # Update local record if status is not success
            if sub.status != 'success':
                sub.status = 'success'
                sub.expiry_date = timezone.now() + timedelta(days=plan_info['days'])
                sub.save()

            if not sub.is_notified:
                send_subscription_email(sub)
                
            return render_success(request, sub)
            
    except Exception as e:
        print(f"Verification Error: {e}")

    return render(request, 'subscription/failed.html', {
        'error': 'Payment verification is taking longer than expected. Please check your email in a few minutes.'
    })


@csrf_exempt
@require_POST
def paystack_webhook(request):
    payload = request.body
    sig_header = request.headers.get('x-paystack-signature')
    
    if not sig_header:
        return HttpResponse(status=400)

    secret = settings.PAYSTACK_SECRET_KEY
    hash = hmac.new(secret.encode('utf-8'), payload, hashlib.sha512).hexdigest()

    if hash != sig_header:
        return HttpResponse(status=401)

    event_data = json.loads(payload)

    if event_data['event'] == 'charge.success':
        reference = event_data['data']['reference']
        
        # 1. Use select_for_update() to prevent race conditions 
        # (Ensures two requests don't process the same reference at once)
        sub = JobSubscription.objects.filter(reference=reference).select_for_update().first()
        
        if sub and sub.status == 'pending':
            plan_info = PLANS.get(sub.plan_type)
            
            # 2. Update Database
            sub.status = 'success'
            sub.expiry_date = timezone.now() + timedelta(days=plan_info['days'])
            sub.save()
            
            # 3. Safe Domain Retrieval
            # If SITE_DOMAIN isn't in settings, it won't crash
            domain = getattr(settings, 'SITE_DOMAIN')
            
            context = {
                'user': sub.user,
                'plan_name': plan_info['name'],
                'amount': sub.amount,
                'expiry': sub.expiry_date,
                'reference': reference,
                'whatsapp_number': sub.whatsapp_number,
                'interest_category': sub.interest_category,
                'domain': domain,
                'protocol': 'https',
                'current_year': timezone.now().year
            }
            
            try:
                send_templated_email(
                    'emails/subscription_confirmation.html',
                    'Your Subscription is Active!',
                    [sub.user.email],
                    context
                )
            except Exception as e:
                print(f"Webhook Email Error: {e}")

    return HttpResponse(status=200)


@login_required
def initialize_course_payment(request, course_slug):
    # Mapping slugs to display names
    courses = {
        'social-media': 'Social Media Management',
        'graphic-design': 'Graphic Design',
        'virtual-assistance': 'Virtual Assistance',
        'content-writing': 'Content Writing',
    }
    
    course_name = courses.get(course_slug)
    if not course_name:
        return JsonResponse({'status': 'error', 'message': 'Invalid course'}, status=400)

    # Configuration
    reference = str(uuid.uuid4())
    amount_naira = 49999 
    amount_kobo = amount_naira * 100 

    # 1. Create the pending purchase record
    CoursePurchase.objects.create(
        user=request.user,
        course_name=course_name,
        amount=amount_naira,
        reference=reference,
        status='pending'
    )

    # 2. Prepare Paystack API call
    url = "https://api.paystack.co/transaction/initialize"
    headers = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}
    payload = {
        "email": request.user.email,
        "amount": amount_kobo,
        "reference": reference,
        "callback_url": "https://readyremotejob.com/courses/verify/"
    }
    
    try:
        r = requests.post(url, headers=headers, json=payload)
        paystack_response = r.json()

        if paystack_response.get('status'):
            # 3. Return 'success' AND the nested data object PaystackPop needs
            return JsonResponse({
                'status': 'success',
                'data': {
                    'access_code': paystack_response['data']['access_code'],
                    'reference': reference,
                    'amount': amount_kobo
                }
            })
        else:
            return JsonResponse({'status': 'error', 'message': 'Paystack initialization failed'}, status=400)

    except requests.exceptions.RequestException as e:
        return JsonResponse({'status': 'error', 'message': 'Connection error'}, status=500)


def verify_course_payment(request):
    reference = request.GET.get('reference')
    purchase = get_object_or_404(CoursePurchase, reference=reference)
    
    # Avoid re-processing if already successful
    if purchase.status == 'success':
        return redirect("https://slack.com/your-invite-link")

    # Verify with Paystack
    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}
    
    try:
        r = requests.get(url, headers=headers)
        response = r.json()
    except Exception:
        messages.error(request, "Could not connect to payment processor.")
        return redirect('courses_list')

    if response.get('status') and response['data']['status'] == 'success':
        purchase.status = 'success'
        purchase.save()

        # --- Send Email using your existing helper function ---
        slack_link = "https://slack.com/your-invite-link"
        email_context = {
            'user': purchase.user,
            'course_name': purchase.course_name,
            'amount': purchase.amount,
            'slack_link': slack_link,
        }
        
        send_templated_email(
            template_name='emails/course_confirmation.html',
            subject=f"Enrollment Confirmed: {purchase.course_name}",
            recipient_list=[purchase.user.email],
            context=email_context
        )

        messages.success(request, f"Payment successful! Welcome aboard. Check your email for the community link.")
        return redirect(slack_link) 
    
    messages.error(request, "Payment verification failed.")
    return redirect('courses_list')


@login_required
def courses_list(request):
    """
    Renders the course landing page.
    Identifies courses already purchased by the user to change buttons to 'Go to Slack'.
    """
    user_purchases = CoursePurchase.objects.filter(
        user=request.user, 
        status='success'
    ).values_list('course_name', flat=True)

    context = {
        'paystack_public_key': settings.PAYSTACK_PUBLIC_KEY,
        'user_purchases': list(user_purchases), 
        'slack_invite_url': "https://join.slack.com/t/your-actual-link"
    }
    return render(request, 'courses.html', context)