# job_portal_app/forms.py

from django import forms
from django.contrib.auth.forms import PasswordChangeForm as AuthPasswordChangeForm
from django.contrib.auth import get_user_model
from .models import *
from django.core.exceptions import ValidationError

User = get_user_model()


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
    Form for creating and updating job listings.
    """
    class Meta:
        model = Job
        fields = [
            'title', 'description', 'company_name', 'location',
            'job_type', 'category', 'is_active', 'external_application_url'
        ]
        widgets = {
            'title': forms.TextInput(attrs={'class': 'input-field'}),
            'description': forms.Textarea(attrs={'class': 'input-field', 'rows': 5}),
            'company_name': forms.TextInput(attrs={'class': 'input-field'}),
            'location': forms.TextInput(attrs={'class': 'input-field'}),
            'job_type': forms.Select(attrs={'class': 'input-field'}),
            'category': forms.Select(attrs={'class': 'input-field'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-checkbox h-5 w-5 text-blue-600'}),
            'external_application_url': forms.URLInput(attrs={'class': 'input-field', 'placeholder': 'https://company.com/apply-here'}),
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

