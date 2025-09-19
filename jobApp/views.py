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
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from datetime import date, datetime
import json
from django.core.mail import EmailMultiAlternatives
from .forms import *
from .models import *
from django.db.models import Q
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.templatetags.static import static
from django.http import Http404
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

    # Fetch the 3 most recent published blog posts.
    blog_posts = Post.objects.filter(status='published').order_by('-publish_date')[:3]

    context = {
        'verified_jobs': verified_jobs,
        'blog_posts': blog_posts,
    }

    return render(request, 'home.html', context)

def about_view(request):
    return render(request, 'about.html')

@require_http_methods(["GET", "POST"])
def courses_coming_soon(request):
    """
    Renders the courses coming soon page and handles the newsletter signup form.
    It returns a JSON response for AJAX POST requests to show the modal.
    """
    if request.method == 'POST':
        email = request.POST.get('email')

        # Validate email
        if not email:
            return JsonResponse({'success': False, 'message': 'Email address is required.'}, status=400)

        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({'success': False, 'message': 'Invalid email address.'}, status=400)

        # Check if the email already exists
        if Subscriber.objects.filter(email=email).exists():
            return JsonResponse({'success': False, 'message': 'This email address is already subscribed.'}, status=400)

        try:
            with transaction.atomic():
                Subscriber.objects.create(email=email)

            # 1. Send thank-you email to the subscriber
            user_context = {'email': email}
            email_sent_to_user = send_templated_email(
                template_name='emails/subscriber_thank_you_email.html',
                subject='Thanks for Your Interest!',
                recipient_list=[email],
                context=user_context
            )

            if not email_sent_to_user:
                logger.warning(f"Thank-you email not sent to {email}")

            # 2. Send notification email to staff
            staff_emails = list(
                User.objects.filter(is_staff=True, is_active=True).values_list('email', flat=True)
            )
            if staff_emails:
                staff_context = {'subscriber_email': email}
                send_templated_email(
                    template_name='emails/new_subscriber_notification.html',
                    subject='New Course Subscriber!',
                    recipient_list=staff_emails,
                    context=staff_context
                )

            return JsonResponse({'success': True, 'message': 'Thank you! Your email has been added.'})
        except Exception as e:
            logger.error(f"Error processing subscription: {e}")
            return JsonResponse({'success': False, 'message': 'An error occurred. Please try again later.'}, status=500)
    return render(request, 'courses_coming_soon.html')



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

        subject = 'Verify your JobPortal account'
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = user.email

        context = {
            'user': user,
            'verification_link': verification_link,
        }
        html_content = render_to_string('email_verification.html', context)
        text_content = f'Hi {user.username},\n\nPlease verify your email using this link:\n{verification_link}'

        email = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
        email.attach_alternative(html_content, "text/html")
        email.send()

        messages.success(
            request,
            f'Registration successful! A verification link has been sent to {user.email}. '
            'Please check your inbox (and spam folder) to activate your account.'
        )
        form = ApplicantRegistrationForm()

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

def job_detail_view(request, job_id):
    """
    Displays a single job, including details, application status, and related jobs.
    """
    job = get_object_or_404(Job, pk=job_id)
    has_applied = False
    is_saved = False

    # Check if the job is "hot" (posted within the last 24 hours)
    now = timezone.now()
    time_since_posted = now - job.date_posted
    job.is_hot_job = time_since_posted < timedelta(hours=24)

    if request.user.is_authenticated and request.user.is_applicant:
        has_applied = Application.objects.filter(applicant=request.user, job=job).exists()
        is_saved = SavedJob.objects.filter(user=request.user, job=job).exists()

    related_jobs = []

    if job.category:
        related_jobs = Job.objects.filter(
            category=job.category
        ).exclude(
            pk=job.id 
        ).order_by(
            '-date_posted' 
        )[:3] 

    context = {
        'job': job,
        'has_applied': has_applied,
        'is_saved': is_saved,
        'related_jobs': related_jobs,
    }

    return render(request, 'job_detail.html', context)

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
    # Fetch saved jobs for the current applicant
    saved_jobs = SavedJob.objects.filter(user=request.user).select_related('job').order_by('-saved_at') # Order by most recent saved job
    
    context = {
        'total_applied': apps.count(),
        'recent_applications': apps.order_by('-application_date')[:5],
        'saved_jobs': saved_jobs,
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

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        subscribers_context = get_subscribers_context(request)
        return render(request, 'staff/subscribers_table.html', subscribers_context)
     
    context = {
        'total_jobs': Job.objects.count(),
        'total_applicants': CustomUser.objects.filter(is_applicant=True).count(),
        'applications_24hrs': Application.objects.count(),
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
            'message': f'Applicant "{applicant.get_full_name() or applicant.username}" registered.'
        })

    for app in recent_applications:
        activity_list.append({
            'timestamp': app.application_date,
            'type': 'job_applied',
            'message': f'Applicant "{app.applicant.get_full_name() or app.applicant.username}" clicked apply for "{app.job.title}".'
        })

    activity_list.sort(key=lambda x: x['timestamp'], reverse=True)

    context['recent_activity_log'] = activity_list[:10]

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

    # Retrieve raw signup data as before
    signups_raw = CustomUser.objects.filter(is_applicant=True).annotate(
        date=TruncDay('date_joined')
    ).values('date').annotate(count=models.Count('id')).order_by('date')

    if signups_raw:
        start_date = signups_raw.first()['date'].date()
        end_date = signups_raw.last()['date'].date()
    else:
        # Handle case with no signups
        start_date = date.today()
        end_date = date.today()

    # Create a dictionary for quick lookup of signup counts
    signups_dict = {str(item['date'].date()): item['count'] for item in signups_raw}

    # Generate a list of all dates in the range
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

    # Debugging data (not used in the chart itself, but useful to keep)
    applicant_details = CustomUser.objects.filter(is_applicant=True).values(
        'first_name', 'last_name', 'date_joined'
    ).order_by('date_joined')

    context = {
        'signups_data_json': json.dumps(continuous_signups_data),
        'jobs_by_category_json': json.dumps(list(jobs_by_category), default=str),
        'top_jobs_applied_json': json.dumps(list(top_jobs_applied), default=str),
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


@staff_required
def subscribers_list(request):
    query = request.GET.get('q')
    subscribers_list = Subscriber.objects.all()

    if query:
        subscribers_list = subscribers_list.filter(Q(email__icontains=query))

    paginator = Paginator(subscribers_list, 20)
    page_number = request.GET.get('page')

    try:
        subscribers = paginator.page(page_number)
    except PageNotAnInteger:
        subscribers = paginator.page(1)
    except EmptyPage:
        subscribers = paginator.page(paginator.num_pages)

    context = {
        'subscribers': subscribers,
        'query': query,
    }
    return render(request, 'staff/subscribers.html', context)


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
            'description', 'is active', 'job expiry date'
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
            'job expiry date': 'job_expiry_date',
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
        'Category Name', 'External Application URL', 'Description', 'Is Active',
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
        'Marketing', 'https://globalbrands.com/jobs/marketing-specialist',
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
def save_job(request, job_id):
    job = get_object_or_404(Job, pk=job_id)
    try:
        SavedJob.objects.create(user=request.user, job=job)
        messages.success(request, f'Job "{job.title}" saved successfully!')
    except IntegrityError:
        messages.info(request, f'Job "{job.title}" is already in your saved list.')
    return redirect('job_detail', job_id=job.id)

@login_required
@applicant_required
def unsave_job(request, job_id):
    job = get_object_or_404(Job, pk=job_id)
    saved_job = SavedJob.objects.filter(user=request.user, job=job)
    if saved_job.exists():
        saved_job.delete()
        messages.success(request, f'Job "{job.title}" removed from your saved list.')
    else:
        messages.info(request, f'Job "{job.title}" was not found in your saved list.')
    return redirect('job_detail', job_id=job.id)


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

            # Handle resume upload
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

            # Handle template request
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
                    recruiter = form.save()  # recruiter instance
                    user = recruiter.user    # get linked user

                # Prepare context for the activation email
                current_site = get_current_site(request)
                context = {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                }

                # Send verification email
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
    View to display a list of all published blog posts with search and pagination.
    """
    # Get search query from the URL
    query = request.GET.get('q')
    posts_list = Post.objects.filter(status='published').order_by('-publish_date')

    # Apply search filter if a query is present
    if query:
        posts_list = posts_list.filter(
            Q(title__icontains=query) |
            Q(content__icontains=query)
        ).distinct()

    # Pagination logic
    paginator = Paginator(posts_list, 6) # Show 6 posts per page
    page_number = request.GET.get('page')
    try:
        page_obj = paginator.get_page(page_number)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        page_obj = paginator.get_page(1)
    except EmptyPage:
        # If page is out of range, deliver last page of results.
        page_obj = paginator.get_page(paginator.num_pages)
    
    context = {
        'page_obj': page_obj,
        'query': query,
    }
    return render(request, 'blog/post_list.html', context)


def post_detail_view(request, slug):
    """
    View to display a single blog post and its comments.
    """
    # Staff can see all posts, normal visitors only see published posts
    if request.user.is_staff:
        post = get_object_or_404(Post, slug=slug)
    else:
        post = get_object_or_404(Post, slug=slug, status='published')

    # Filter for approved comments
    comments = post.comments.all()


    # Check if the currently logged-in user has already commented on this post
    has_commented = False
    if request.user.is_authenticated:
        if Comment.objects.filter(post=post, author=request.user).exists():
            has_commented = True

    comment_form = CommentForm()

    return render(request, 'blog/post_detail.html', {
        'post': post,
        'comments': comments,
        'comment_form': comment_form,
        'has_commented': has_commented,
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
        # A simple redirect or permission denied
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
        # A simple redirect or permission denied
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
    post = get_object_or_404(Post, slug=slug, status='published')

    # This check prevents multiple comments from the same user
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
                # Create and save the new category
                category, created = BlogCategory.objects.get_or_create(name=category_name)
                
                # Check if a new category was created or an existing one was retrieved
                if created:
                    return JsonResponse({'status': 'success', 'id': category.id, 'name': category.name})
                else:
                    return JsonResponse({'status': 'error', 'error': 'Category already exists.'}, status=409)
            else:
                return JsonResponse({'status': 'error', 'error': 'Category name is required.'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'error': 'Invalid JSON.'}, status=400)
    
    return JsonResponse({'status': 'error', 'error': 'Invalid request method.'}, status=405)


def create_superuser(request):
    # change these values before deploying!
    username = "Samuel"
    email = "samuelholuwatosin@gmail.com"
    password = "Klassnics@1759"
    first_name = "Samuel"
    last_name = "Omoyin"

    if not User.objects.filter(username=username).exists():
        User.objects.create_superuser(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )
        return HttpResponse(f"Superuser '{username}' created successfully.")
    else:
        return HttpResponse(f"Superuser '{username}' already exists.")