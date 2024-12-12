from celery import shared_task
from datetime import timedelta
from django.utils.timezone import now
from .models import OTP


@shared_task
def remove_expired_otps():
    """
    Delete OTPs that are older than 5 minutes.
    """
    expiration_time = now() - timedelta(minutes=5)
    OTP.objects.filter(created_at__lt=expiration_time).delete()
    return "Expired OTPs removed."
