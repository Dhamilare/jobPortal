from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import *
from django.utils.html import format_html
from django_ckeditor_5.widgets import CKEditor5Widget
from django import forms


# ==========================
# CKEditor5 Admin Integration
# ==========================
class PostAdminForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = '__all__'
        widgets = {
            'content': CKEditor5Widget(config_name='default'),
        }


class JobAdminForm(forms.ModelForm):
    class Meta:
        model = Job
        fields = '__all__'
        widgets = {
            'content': CKEditor5Widget(config_name='default'),
        }

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
    form = JobAdminForm
    list_display = ('title', 'slug', 'company_name', 'location', 'job_type', 'category', 'is_active', 'date_posted', 'job_expiry_date', 'posted_by') # Added job_expiry_date
    list_filter = ('job_type', 'category', 'is_active', 'date_posted', 'job_expiry_date')
    search_fields = ('title', 'company_name', 'location', 'description')
    raw_id_fields = ('category', 'posted_by')
    date_hierarchy = 'date_posted'
    actions = ['make_active', 'make_inactive']

    fieldsets = (
        (None, {
            'fields': ('title', 'slug', 'company_name', 'location', 'job_type', 'category', 'external_application_url', 'description', 'is_active', 'job_expiry_date') # Added job_expiry_date
        }),
        ('Dates', {
            'fields': ('date_posted',),
            'classes': ('collapse',),
        }),
        ('Posting Info', {
            'fields': ('posted_by',),
            'classes': ('collapse',),
        }),
    )
    readonly_fields = ('date_posted','slug',)

    def make_active(self, request, queryset):
        queryset.update(is_active=True)
        self.message_user(request, f"{queryset.count()} jobs marked as active.")
    make_active.short_description = "Mark selected jobs as active"

    def make_inactive(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} jobs marked as inactive.")
    make_inactive.short_description = "Mark selected jobs as inactive"


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
    list_display = ('name', 'slug', 'description')
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


# Admin for SavedJob model
@admin.register(SavedJob)
class SavedJobAdmin(admin.ModelAdmin):
    list_display = ('user', 'job', 'saved_at')
    list_filter = ('saved_at',)
    search_fields = ('user__username', 'job__title', 'job__company_name')
    raw_id_fields = ('user', 'job')


@admin.register(JobAlert)
class JobAlertAdmin(admin.ModelAdmin):
    list_display = ('user', 'alert_name', 'keywords_display', 'locations', 'job_types_display', 'frequency', 'is_active', 'created_at', 'last_sent')
    list_filter = ('frequency', 'is_active', 'created_at', 'last_sent')
    search_fields = ('user__username', 'alert_name', 'keywords', 'locations', 'job_types')
    raw_id_fields = ('user',) 
    filter_horizontal = ('categories',) 

    def keywords_display(self, obj):
        return obj.keywords or '-'
    keywords_display.short_description = 'Keywords'

    def job_types_display(self, obj):
        return obj.job_types or '-'
    job_types_display.short_description = 'Job Types'


@admin.register(Recruiter)
class RecruiterAdmin(admin.ModelAdmin):
    
    list_display = (
        'company_name',
        'user_email',
        'phone_number',
        'created_at'
    )

    list_filter = (
        'created_at',
        'updated_at',
    )

    search_fields = (
        'company_name',
        'phone_number',
        'user__email'
    )

    fieldsets = (
        (None, {
            'fields': ('user', 'company_name', 'address', 'phone_number')
        }),
        ('Important dates', {
            'fields': ('created_at', 'updated_at')
        }),
    )

    raw_id_fields = ('user',)
    readonly_fields = ('created_at', 'updated_at')
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'
    user_email.admin_order_field = 'user__email'


@admin.register(BlogCategory)
class BlogCategoryAdmin(admin.ModelAdmin):
    """
    Admin configuration for the BlogCategory model.
    """
    list_display = ('name', 'slug')
    prepopulated_fields = {'slug': ('name',)}


@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    form = PostAdminForm
    """
    Admin configuration for the Post model.
    """
    list_display = ('title', 'author', 'publish_date', 'category', 'image_tag')
    list_filter = ('publish_date', 'author')
    search_fields = ('title', 'content')
    prepopulated_fields = {'slug': ('title',)}
    raw_id_fields = ('author',)
    date_hierarchy = 'publish_date'
    ordering = ('publish_date',)
    readonly_fields = ('created_at', 'updated_at', 'image_tag')


    def image_tag(self, obj):
        """
        Displays a thumbnail of the blog post image in the admin.
        """
        if obj.image:
            return format_html('<img src="{}" style="max-height: 100px; max-width: 150px;" />'.format(obj.image.url))
        return "No Image"
    image_tag.short_description = 'Image Preview'


@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    """
    Admin configuration for the Comment model.
    """
    list_display = ('author', 'post', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('author__username', 'content')


# ---------------------------------
# ---ApplicantProfile Inline ---
# ---------------------------------
class ApplicantProfileInline(admin.StackedInline):
    """
    This will show the ApplicantProfile fields directly on the
    CustomUser admin page for easy editing.
    """
    model = ApplicantProfile
    can_delete = False
    verbose_name_plural = 'Applicant Profile'
    fk_name = 'user'
    
    readonly_fields = ('resume_text', 'parsed_skills', 'parsed_experience', 'parsed_summary')
    
    fields = ('resume', 'resume_text', 'parsed_skills', 'parsed_summary', 'parsed_experience')
    
    max_num = 1
    min_num = 1

    def get_formset(self, request, obj=None, **kwargs):
        """
        Only show this inline if the user is an applicant.
        """
        if obj and obj.is_applicant:
            return super().get_formset(request, obj, **kwargs)
        return super().get_formset(request, obj, **kwargs)
        
    def has_add_permission(self, request, obj=None):
        if obj and hasattr(obj, 'applicant_profile'):
             return False
        return True
    

# ---------------------------------
# --- ApplicantProfile
# ---------------------------------
@admin.register(ApplicantProfile)
class ApplicantProfileAdmin(admin.ModelAdmin):
    """
    Admin view to see all ApplicantProfiles at once.
    """
    list_display = ('user', 'last_updated')
    search_fields = ('user__email', 'user__username', 'user__first_name')
    
    readonly_fields = ('parsed_skills', 'parsed_experience', 'parsed_summary', 'last_updated')
    raw_id_fields = ('user',)


# ---------------------------------
# --- StaffProfile
# ---------------------------------

@admin.register(StaffProfile)
class StaffProfileAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "job_title",
    )

    search_fields = (
        "user__username",
        "user__email",
        "job_title",
    )

    list_filter = (
        "job_title",
    )

    readonly_fields = (
        "user",
    )

    fieldsets = (
        ("User Information", {
            "fields": ("user",)
        }),
        ("Profile Details", {
            "fields": (
                "job_title",
                "bio",
                "profile_picture",
            )
        }),
    )


@admin.register(JobSubscription)
class JobSubscriptionAdmin(admin.ModelAdmin):
    list_display = (
        'user', 
        'plan_type', 
        'amount', 
        'status', 
        'interest_category', 
        'whatsapp_number', 
        'created_at', 
        'expiry_date'
    )
    
    list_filter = ('status', 'plan_type', 'created_at')
    
    search_fields = (
        'user__email', 
        'user__username', 
        'reference', 
        'whatsapp_number', 
        'interest_category'
    )
    
    readonly_fields = ('reference', 'created_at')
    
    fieldsets = (
        ('User Information', {
            'fields': ('user', 'whatsapp_number', 'interest_category')
        }),
        ('Subscription Details', {
            'fields': ('plan_type', 'amount', 'status', 'reference')
        }),
        ('Dates', {
            'fields': ('created_at', 'expiry_date')
        }),
    )

    ordering = ('-created_at',)

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')
    

@admin.register(CoursePurchase)
class CoursePurchaseAdmin(admin.ModelAdmin):
    list_display = ('user', 'course_name', 'amount', 'status', 'reference', 'created_at')
    
    list_filter = ('status', 'course_name', 'created_at')
    
    search_fields = ('user__email', 'user__username', 'reference', 'course_name')
    
    readonly_fields = ('reference', 'created_at')
    
    ordering = ('-created_at',)

    def get_status_display(self, obj):
        from django.utils.html import format_html
        colors = {
            'success': 'green',
            'pending': 'orange',
            'failed': 'red'
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.status, 'black'),
            obj.status.upper()
        )
    get_status_display.short_description = 'Payment Status'


@admin.register(Ambassador)
class AmbassadorAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'user_full_name', 'phone_number', 'bank_name', 'referral_code', 'joined_at')
    search_fields = ('user__email', 'user__username', 'user__first_name', 'user__last_name', 'referral_code', 'phone_number')
    list_filter = ('joined_at', 'bank_name')
    ordering = ('-joined_at',)

    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'Email'

    def user_full_name(self, obj):
        return obj.user.get_full_name() or obj.user.username
    user_full_name.short_description = 'Name'



class InterviewStaticQAInline(admin.TabularInline):
    model = InterviewStaticQA
    extra = 3  # Provides 3 empty rows by default
    classes = ('collapse',) # Optional: Keeps the UI clean if you have many QAs

@admin.register(InterviewCategory)
class InterviewCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'icon_class')
    prepopulated_fields = {'slug': ('name',)} # Automatically generates slug from name
    search_fields = ('name', 'description')
    inlines = [InterviewStaticQAInline]
    
    fieldsets = (
        ('General Information', {
            'fields': ('name', 'slug', 'icon_class', 'description')
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related('static_qa')





    



