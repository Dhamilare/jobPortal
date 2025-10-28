from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import ApplicantProfile

@receiver(post_save, sender=ApplicantProfile)
def extract_resume_text_after_upload(sender, instance, created, **kwargs):
    """
    When an ApplicantProfile is created or updated with a resume,
    automatically extract and store resume text.
    """
    if instance.resume and (created or not instance.resume_text):
        extracted_text = instance.extract_resume_text()
        if extracted_text:
            instance.resume_text = extracted_text[:50000]  # truncate long text
            instance.save(update_fields=["resume_text"])
