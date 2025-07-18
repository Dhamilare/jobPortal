from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django import forms
from .models import CustomUser, Job, Application, Category, EmailVerificationToken


# -----------------------
# Custom User Admin Forms
# -----------------------

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ("email", "username", "is_applicant", "is_moderator", "is_staff", "is_superuser")


class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = CustomUser
        fields = ("email", "username", "first_name", "last_name", "is_active", "is_applicant", "is_moderator", "is_staff", "is_superuser")


# -----------------------
# Custom User Admin
# -----------------------

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    """
    Custom Admin interface for CustomUser model.
    """
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = CustomUser

    list_display = ('email', 'username', 'is_applicant', 'is_moderator', 'is_staff', 'is_active', 'date_joined')
    list_filter = ('is_applicant', 'is_moderator', 'is_staff', 'is_active')
    search_fields = ('email', 'username', 'first_name', 'last_name')
    ordering = ('email',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('username', 'first_name', 'last_name')}),
        ('Permissions', {
            'fields': (
                'is_active', 'is_applicant', 'is_moderator', 'is_staff', 'is_superuser',
                'groups', 'user_permissions'
            )
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'email', 'username', 'password1', 'password2',
                'is_applicant', 'is_moderator', 'is_staff', 'is_superuser'
            ),
        }),
    )


# -----------------------
# Job Admin
# -----------------------

@admin.register(Job)
class JobAdmin(admin.ModelAdmin):
    """
    Admin interface for Job model.
    """
    list_display = (
        'title', 'company_name', 'location', 'category',
        'job_type', 'external_application_url', 'posted_by',
        'date_posted', 'is_active'
    )
    list_filter = ('job_type', 'category', 'is_active', 'date_posted')
    search_fields = ('title', 'company_name', 'description', 'location')
    date_hierarchy = 'date_posted'
    raw_id_fields = ('posted_by',)
    fieldsets = (
        (None, {
            'fields': (
                'title', 'description', 'company_name', 'location',
                'job_type', 'category', 'is_active', 'external_application_url'
            )
        }),
        ('Metadata', {
            'fields': ('posted_by', 'date_posted'),
            'classes': ('collapse',),
        }),
    )


# -----------------------
# Application Admin
# -----------------------

@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    """
    Admin interface for Application model.
    """
    list_display = ('applicant', 'job', 'application_date', 'status')
    list_filter = ('status', 'application_date')
    list_editable = ('status',)
    search_fields = ('applicant__username', 'applicant__email', 'job__title', 'job__company_name')
    date_hierarchy = 'application_date'
    raw_id_fields = ('applicant', 'job')


# -----------------------
# Category Admin
# -----------------------

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    """
    Admin interface for Category model.
    """
    list_display = ('name', 'description')
    search_fields = ('name',)


# -----------------------
# Email Verification Token Admin
# -----------------------

@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    """
    Admin interface for EmailVerificationToken model.
    """
    list_display = ('user', 'token', 'created_at', 'expires_at', 'is_valid')
    list_filter = ('created_at', 'expires_at')
    search_fields = ('user__email', 'token')
    readonly_fields = ('token', 'created_at', 'expires_at')

