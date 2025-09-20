# job_portal_app/forms.py

from django import forms
from django.contrib.auth.forms import PasswordChangeForm as AuthPasswordChangeForm
from django.contrib.auth import get_user_model
from .models import *
from django.core.exceptions import ValidationError
from django.contrib.auth.forms import SetPasswordForm
from django.db import transaction
from django.contrib.auth.password_validation import validate_password
import re

User = get_user_model()

class CustomSetPasswordForm(SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['new_password1'].help_text = ''
        self.fields['new_password2'].help_text = ''

# ==============================
# Applicant Registration Form
# ==============================
class ApplicantRegistrationForm(forms.ModelForm):
    """
    Custom form for applicant registration.
    """
    username = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={'class': 'input-field', 'placeholder': 'Enter your username'})
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'input-field', 'placeholder': 'your@example.com'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'input-field', 'placeholder': 'Enter your password'})
    )
    password_confirm = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'input-field', 'placeholder': 'Confirm your password'})
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email address is already registered.")
        return email

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')

        if password and password_confirm and password != password_confirm:
            self.add_error('password_confirm', "Passwords do not match.")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        user.is_active = False  # Require email verification
        user.is_applicant = True
        if commit:
            user.save()
        return user


# ==============================
# Custom Login Form
# ==============================
class LoginForm(forms.Form):
    """
    Custom form for user login using email.
    """
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'input-field', 'placeholder': 'your@example.com'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'input-field', 'placeholder': 'Enter your password'})
    )

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        password = cleaned_data.get('password')

        if email and password:
            user = User.objects.filter(email=email).first()
            if not user:
                raise forms.ValidationError("No account found with this email address.")
            if not user.check_password(password):
                raise forms.ValidationError("Incorrect password.")
            if not user.is_active:
                raise forms.ValidationError("Account is not active. Please verify your email.")
            self.user = user  # Store for use in the view
        return cleaned_data


# ==============================
# Job Creation/Update Form
# ==============================
class JobForm(forms.ModelForm):
    """
    Form for creating and updating Job listings.
    """
    class Meta:
        model = Job
        fields = [
            'title', 'company_name', 'location', 'job_type',
            'category', 'external_application_url', 'description', 'job_expiry_date', 'is_active'
        ]
        widgets = {
            'title': forms.TextInput(attrs={'class': 'input-field', 'placeholder': 'e.g., Senior Software Engineer'}),
            'company_name': forms.TextInput(attrs={'class': 'input-field', 'placeholder': 'e.g., Tech Solutions Inc.'}),
            'location': forms.TextInput(attrs={'class': 'input-field', 'placeholder': 'e.g., Remote, New York, London'}),
            'job_type': forms.Select(attrs={'class': 'input-field'}),
            'category': forms.Select(attrs={'class': 'input-field'}),
            'external_application_url': forms.URLInput(attrs={'class': 'input-field', 'placeholder': 'https://example.com/apply'}),
            'description': forms.Textarea(attrs={'class': 'input-field', 'rows': 6, 'placeholder': 'Detailed job description...'}),
            'job_expiry_date': forms.DateTimeInput(attrs={'class': 'input-field', 'type': 'datetime-local'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-checkbox h-5 w-5 text-blue-600'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['category'].queryset = Category.objects.all()
        self.fields['category'].empty_label = "Select a Category"


# ==============================
# Applicant Profile Update
# ==============================
class ApplicantProfileUpdateForm(forms.ModelForm):
    """
    Form for applicants to update profile (excluding password/email).
    """
    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'input-field'}),
            'first_name': forms.TextInput(attrs={'class': 'input-field'}),
            'last_name': forms.TextInput(attrs={'class': 'input-field'}),
        }


# ==============================
# Password Change Form
# ==============================
class CustomPasswordChangeForm(AuthPasswordChangeForm):
    """
    Custom form for changing user password.
    """
    old_password = forms.CharField(
        label="Old password",
        strip=False,
        widget=forms.PasswordInput(attrs={'class': 'input-field', 'placeholder': 'Enter old password'})
    )
    new_password1 = forms.CharField(
        label="New password",
        strip=False,
        widget=forms.PasswordInput(attrs={'class': 'input-field', 'placeholder': 'Enter new password'})
    )
    new_password2 = forms.CharField(
        label="Confirm new password",
        strip=False,
        widget=forms.PasswordInput(attrs={'class': 'input-field', 'placeholder': 'Confirm new password'})
    )

    class Meta:
        model = User
        fields = ['old_password', 'new_password1', 'new_password2']


# ==============================
# Email Change Form
# ==============================
class ApplicantEmailChangeForm(forms.ModelForm):
    """
    Form for applicants to change their email address.
    """
    new_email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'input-field', 'placeholder': 'Enter new email address'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'input-field', 'placeholder': 'Enter current password'})
    )

    class Meta:
        model = User
        fields = ['new_email']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if not self.user:
            raise ValueError("ApplicantEmailChangeForm requires a 'user' instance.")

    def clean_new_email(self):
        new_email = self.cleaned_data['new_email']
        if User.objects.filter(email=new_email).exclude(pk=self.user.pk).exists():
            raise forms.ValidationError("This email address is already in use.")
        return new_email

    def clean_password(self):
        password = self.cleaned_data['password']
        if not self.user.check_password(password):
            raise forms.ValidationError("Incorrect current password.")
        return password

    def save(self, commit=True):
        self.user.email = self.cleaned_data['new_email']
        self.user.is_active = False  # Require re-verification
        if commit:
            self.user.save()
        return self.user


# ==============================
# Moderator Creation Form
# ==============================
class ModeratorCreationForm(forms.ModelForm):
    """
    Form for staff to create new moderator accounts.
    """
    username = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={'class': 'input-field', 'placeholder': 'Enter username'})
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'input-field', 'placeholder': 'moderator@example.com'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'input-field', 'placeholder': 'Set password'})
    )
    password_confirm = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'input-field', 'placeholder': 'Confirm password'})
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email address is already registered.")
        return email

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')

        if password and password_confirm and password != password_confirm:
            self.add_error('password_confirm', "Passwords do not match.")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        user.is_active = True
        user.is_moderator = True
        user.is_applicant = False
        if commit:
            user.save()
        return user
    

class ModeratorUpdateForm(forms.ModelForm):
    username = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={'class': 'input-field', 'placeholder': 'Enter username'})
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'input-field', 'placeholder': 'moderator@example.com'})
    )
    first_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={'class': 'input-field', 'placeholder': 'Enter First Name'})
    )
    last_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={'class': 'input-field', 'placeholder': 'Enter Last Name'})
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email and User.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("This email address is already registered.")
        
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        if commit:
            user.save()
        return user
    

class CategoryForm(forms.ModelForm):
    """
    Form for managing Category objects (create and update).
    """
    class Meta:
        model = Category
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'input-field', 'placeholder': 'e.g., Software Development'}),
            'description': forms.Textarea(attrs={'class': 'input-field', 'rows': 3, 'placeholder': 'Brief description of this category (optional)'}),
        }

class JobCSVUploadForm(forms.Form):
    """
    Form for uploading a CSV file containing job data.
    """
    csv_file = forms.FileField(
        label="Upload CSV File",
        widget=forms.ClearableFileInput(attrs={
            'class': 'block w-full text-sm text-gray-700 border border-gray-300 rounded-lg cursor-pointer bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100'
        })
    )

    def clean_csv_file(self):
        csv_file = self.cleaned_data.get('csv_file')

        if not csv_file:
            raise ValidationError("Please upload a CSV file.")

        # Validate file extension
        if not csv_file.name.lower().endswith('.csv'):
            raise ValidationError("Only .csv files are allowed.")

        # Validate MIME type (some browsers may send 'application/octet-stream')
        allowed_types = ['text/csv', 'application/vnd.ms-excel', 'application/octet-stream']
        if csv_file.content_type not in allowed_types:
            raise ValidationError(f"Invalid file type: {csv_file.content_type}. Please upload a valid CSV file.")

        return csv_file


class JobAlertForm(forms.ModelForm):
    """
    Form for creating and updating JobAlerts.
    """
    # Override categories field to use CheckboxSelectMultiple for better UX
    categories = forms.ModelMultipleChoiceField(
        queryset=Category.objects.all(),
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'form-checkbox-group'}),
        required=False,
        label="Job Categories"
    )

    class Meta:
        model = JobAlert
        fields = ['alert_name', 'keywords', 'categories', 'locations', 'job_types', 'frequency', 'is_active']
        widgets = {
            'alert_name': forms.TextInput(attrs={'class': 'input-field', 'placeholder': 'e.g., Remote Python Jobs'}),
            'keywords': forms.TextInput(attrs={'class': 'input-field', 'placeholder': 'e.g., Python, Django, API (comma-separated)'}),
            'locations': forms.TextInput(attrs={'class': 'input-field', 'placeholder': 'e.g., London, Remote, New York (comma-separated)'}),
            'job_types': forms.TextInput(attrs={'class': 'input-field', 'placeholder': 'e.g., Full-time, Remote (comma-separated)'}),
            'frequency': forms.Select(attrs={'class': 'input-field'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-checkbox h-5 w-5 text-blue-600'})
        }
        help_texts = {
            'keywords': 'Comma-separated keywords (e.g., "Python, Django, API")',
            'locations': 'Comma-separated locations (e.g., "London, Remote, New York")',
            'job_types': 'Comma-separated job types (e.g., "Full-time, Remote"). Available types: Full-time, Part-time, Contract, Temporary, Internship, Remote.',
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Dynamically set choices for job_types help text based on Job model
        job_type_choices_str = ", ".join([choice[0] for choice in Job.JOB_TYPE_CHOICES])
        self.fields['job_types'].help_text = f"Comma-separated job types (e.g., 'Full-time, Remote'). Available types: {job_type_choices_str}."



class ResumeUploadForm(forms.Form):
    """
    Form for applicants to upload their resume and/or request a resume template.
    """
    full_name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'placeholder': 'Your Full Name',
            'class': 'w-full p-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-shadow'
        })
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'placeholder': 'Your Email Address',
            'class': 'w-full p-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-shadow'
        })
    )
    resume = forms.FileField(
        label="Upload your Resume (Optional)",
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'block w-full text-sm text-gray-900 border border-gray-300 rounded-lg cursor-pointer bg-gray-50 focus:outline-none'
        })
    )
    request_template = forms.BooleanField(
        label="Send a resume template to my email",
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'h-4 w-4 text-blue-600 rounded border-gray-300'
        })
    )


# -------------------------------
# Recruiter Registration Form
# -------------------------------

class RecruiterRegistrationForm(forms.Form):
    first_name = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'block w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring focus:ring-blue-300',
            'placeholder': 'First Name'
        })
    )
    last_name = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'block w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring focus:ring-blue-300',
            'placeholder': 'Last Name'
        })
    )
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'block w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring focus:ring-blue-300',
            'placeholder': 'Email Address'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'block w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring focus:ring-blue-300',
            'placeholder': 'Password'
        })
    )
    password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={
            'class': 'block w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring focus:ring-blue-300',
            'placeholder': 'Confirm Password'
        })
    )
    company_name = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={
            'class': 'block w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring focus:ring-blue-300',
            'placeholder': 'Company Name'
        })
    )
    address = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'block w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring focus:ring-blue-300',
            'placeholder': 'Company Address',
            'rows': 3
        })
    )
    phone_number = forms.CharField(
        max_length=20,
        widget=forms.TextInput(attrs={
            'class': 'block w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring focus:ring-blue-300',
            'placeholder': 'Phone Number'
        })
    )

    def clean_email(self):
        email = self.cleaned_data.get('email')
        # Check if email already exists
        if CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError("Email already exists.")

        # Disallow free email providers
        personal_domains = [
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'live.com', 'icloud.com', 'aol.com', 'mail.com', 'protonmail.com'
        ]

        domain = email.split('@')[-1].lower()
        
        # 1. Exact match with known personal domains
        if domain in personal_domains:
            raise forms.ValidationError("Please use your company email address, not a personal email.")

        # 2. Regex check for patterns like gmail.*, yahoo.*, etc.
        if re.match(r"^(gmail|yahoo|hotmail|outlook|aol|icloud|protonmail)\.", domain):
            raise forms.ValidationError("Please use your company email address, not a personal email.")

        # 3. Disallow suspicious TLDs
        if domain.endswith('.xyz') or domain.endswith('.top'):
            raise forms.ValidationError("Please use a valid business email domain.")

        return email

    def clean_password(self):
        password = self.cleaned_data.get('password')
        validate_password(password)
        return password

    def clean_password2(self):
        password = self.cleaned_data.get('password')
        password2 = self.cleaned_data.get('password2')
        if password and password2 and password != password2:
            raise forms.ValidationError("Passwords do not match.")
        return password2

    @transaction.atomic
    def save(self, commit=True):
        user = CustomUser.objects.create_user(
            email=self.cleaned_data['email'],
            password=self.cleaned_data['password'],
            first_name=self.cleaned_data['first_name'],
            last_name=self.cleaned_data['last_name'],
            is_moderator=True,
            is_applicant=False
        )

        recruiter = Recruiter.objects.create(
            company_name=self.cleaned_data['company_name'],
            address=self.cleaned_data['address'],
            phone_number=self.cleaned_data['phone_number'],
            user=user
        )

        return recruiter
    

class PostForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = ('title', 'content', 'image', 'category')
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500'
            }),
            'image': forms.ClearableFileInput(attrs={
                'class': 'w-full p-2 border rounded bg-gray-50'
            }),
            'category': forms.Select(attrs={
                'class': 'w-full p-2 border rounded bg-white focus:outline-none focus:ring-2 focus:ring-blue-500'
            }),
        }


class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ('content',)
        widgets = {
            'content': forms.Textarea(attrs={
                'class': 'w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500',
                'rows': 5
            }),
        }
        labels = {
            'content': 'Your Comment',
        }
