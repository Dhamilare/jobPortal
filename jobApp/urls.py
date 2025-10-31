# job_portal_app/urls.py
from django.urls import path
from django.shortcuts import render
from . import views
from django.contrib.auth import views as auth_views
from .forms import CustomSetPasswordForm

urlpatterns = [
    # -------------------- Public Pages --------------------
    path('', views.home_view, name='home'),
    path('about/', views.about_view, name='about'),
    path('accounts/register/', views.applicant_register, name='register'),
    path('verify-email/<uuid:token>/', views.email_verification_confirm, name='email_verification_confirm'),
    path('accounts/login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('account/delete/', views.delete_account_view, name='delete_account'),

    # URL for recruiter registration and job posting landing page
    path('post-job/', views.recruiter_register, name='post_job'),
    path('activate/<uidb64>/<token>/', views.activate_account, name='activate_account'),
    
    path('password-reset/', views.custom_password_reset, name='custom_password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='accounts/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='accounts/password_reset_confirm.html', form_class=CustomSetPasswordForm), name='password_reset_confirm'),
    path('reset/complete/', auth_views.PasswordResetCompleteView.as_view(template_name='accounts/password_reset_complete.html'), name='password_reset_complete'),
    
    path('courses/', views.courses_coming_soon, name='courses_coming_soon'),
    path('resume/', views.submit_resume_view, name='submit_resume'),


    # -------------------- Job Listings --------------------
    path('jobs/', views.job_list_view, name='job_list'),
    path('jobs/<slug:slug>/', views.job_detail_view, name='job_detail'),
    path('jobs/<slug:slug>/apply-redirect/', views.job_apply_link_redirect, name='job_apply_redirect'),
    path('jobs/<slug:slug>/save/', views.save_job, name='save_job'),
    path('jobs/<slug:slug>/unsave/', views.unsave_job, name='unsave_job'),
    
    # -------------------- Applicant Module --------------------
    path('applicant/dashboard/', views.applicant_dashboard, name='applicant_dashboard'),
    path('applicant/profile/update/', views.applicant_profile_update, name='applicant_profile_update'),
    path('applicant/password/change/', views.applicant_password_change, name='applicant_password_change'),
    path('applicant/email/change/', views.applicant_email_change, name='applicant_email_change'),
    path('applicant/applications/', views.applicant_applications_list, name='applicant_applications_list'),
    
    # Job Alerts URLs
    path('applicant/job-alerts/', views.manage_job_alerts, name='manage_job_alerts'),
    path('applicant/job-alerts/<int:alert_id>/edit/', views.manage_job_alerts, name='edit_job_alert'),

   # -------------------- Moderator Module --------------------
    path('moderator/dashboard/', views.moderator_dashboard, name='moderator_dashboard'),
    path('moderator/jobs/', views.job_list_create, name='job_list_create'), 
    path('moderator/jobs/bulk-upload/sample/', views.job_bulk_upload_csv_sample, name='job_bulk_upload_csv_sample'),
    path('moderator/jobs/bulk-upload/', views.job_bulk_upload_csv, name='job_bulk_upload_csv'),
    path('moderator/jobs/<slug:slug>/', views.job_update_delete, name='job_update_delete'), 
    path('moderator/reports/', views.moderator_report_view, name='moderator_reports'),
    path('jobs/bulk-delete/', views.job_bulk_delete, name='job_bulk_delete'),

    # Category Management URLs
    path('moderator/categories/', views.manage_categories, name='manage_categories'),
    path('moderator/categories/<slug:slug>/edit-delete/', views.category_update_delete, name='category_update_delete'),

    # -------------------- Staff Only --------------------
    path('staff/create-moderator/', views.is_staff_create_moderator, name='is_staff_create_moderator'),
    path('staff/export-applicants/', views.is_staff_export_applicants_csv, name='is_staff_export_applicants_csv'),
    path('staff/moderators/manage/', views.manage_moderators, name='manage_moderators'),
    path('staff/moderators/manage/<int:user_id>/', views.manage_moderators, name='manage_moderators_edit_delete'),
    path('staff/subscribers', views.subscribers_list, name='subscribers_list'),

    
    # Blog Post Management
    path('blogs/', views.post_list_view, name='blog_list'),
    path('blogs/new_post', views.post_create_view, name='blog_create'),
    path('blogs/<slug:slug>/', views.post_detail_view, name='blog_detail'),
    path('blogs/<slug:slug>/edit/', views.post_update_view, name='blog_update'),
    path('blogs/<slug:slug>/delete/', views.post_delete_view, name='blog_delete'),
    path('blogs/<slug:slug>/comment/', views.add_comment_to_post, name='add_comment_to_post'),
    path('create-category/', views.create_category, name='create_category'),

    # -------------------- Feedback Pages --------------------
    path('register/success/', lambda request: render(request, 'registration_success.html'), name='registration_success'),
    path('email-change/success/', lambda request: render(request, 'email_change_success.html'), name='email_change_success'),
    path('email-verification/failed/', lambda request: render(request, 'email_verification_failed.html'), name='email_verification_failed'),
    path('email-verification/success/', lambda request: render(request, 'email_verification_success.html'), name='email_verification_success'),

    # --- URLS FOR RESUME ANALYZER ---

    # The page the user visits to see the analysis
    path('job/<slug:job_slug>/analyze/', 
         views.resume_analyzer_view, 
         name='resume_analyzer'),
         
    # The API endpoint the page calls to get the AI result
    path('api/job/<slug:job_slug>/run_analysis/', 
         views.run_analysis_api_view, 
         name='api_run_analysis'),

      # The URL endpoint to handle the resume file upload POST request
    path('job/<slug:job_slug>/analyze/upload/',
         views.handle_resume_upload_view,
         name='handle_resume_upload'),
]
