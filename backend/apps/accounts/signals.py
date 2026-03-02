from django.db.models.signals import post_save
from django.dispatch import receiver
import logging

logger = logging.getLogger(__name__)


# Signals are imported in apps.py ready() method
# Add any post-save signals here as needed
