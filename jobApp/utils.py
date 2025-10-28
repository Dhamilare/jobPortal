from django.db.models import Q
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .models import *
from django.conf import settings
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from datetime import datetime
import os
import fitz 
import docx2txt


def send_templated_email(template_name, subject, recipient_list, context, attachments=None):
    context['current_year'] = datetime.now().year
    
    html_content = render_to_string(template_name, context)
    
    email = EmailMessage(
        subject,
        html_content,
        settings.DEFAULT_FROM_EMAIL,
        recipient_list
    )
    
    email.content_subtype = "html" 
    
    if attachments:
        for filename, content, mimetype in attachments:
            email.attach(filename, content, mimetype)
    
    try:
        email.send()
        return True
    except Exception as e:
        import traceback
        print(f"Error sending email: {e}\n{traceback.format_exc()}")
        return False

def get_subscribers_context(request):
    """
    Helper function to get subscribers list and pagination context.
    """
    query = request.GET.get('q', '')
    
    subscribers_queryset = Subscriber.objects.all()
    if query:
        subscribers_queryset = subscribers_queryset.filter(Q(email__icontains=query))
    
    paginator = Paginator(subscribers_queryset, 10)
    page_number = request.GET.get('page')

    try:
        subscribers_list = paginator.page(page_number)
    except PageNotAnInteger:
        subscribers_list = paginator.page(1)
    except EmptyPage:
        subscribers_list = paginator.page(paginator.num_pages)

    return {
        'subscribers_list': subscribers_list,
        'query': query,
    }


def extract_resume_text(file_path: str) -> str:
    """
    Extracts readable text from a resume file (PDF or DOCX).
    Returns the plain text or None if extraction fails.
    """
    try:
        ext = os.path.splitext(file_path)[1].lower()

        if ext == ".pdf":
            text = ""
            with fitz.open(file_path) as doc:
                for page in doc:
                    text += page.get_text()
            return text.strip()

        elif ext == ".docx":
            text = docx2txt.process(file_path)
            return text.strip()

        else:
            return None

    except Exception as e:
        print(f"❌ Resume text extraction failed: {e}")
        return None