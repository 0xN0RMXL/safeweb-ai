import os

from .base import *  # noqa: F401, F403

DEBUG = False

# Require a real SECRET_KEY in production
SECRET_KEY = os.environ['SECRET_KEY']

# Security settings for production
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# CORS — load production origins from env
CORS_ALLOWED_ORIGINS = os.getenv(
    'CORS_ALLOWED_ORIGINS',
    'https://safeweb.ai,https://www.safeweb.ai',
).split(',')

# Use real email backend in production
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

# Celery with real Redis in production
CELERY_TASK_ALWAYS_EAGER = False
