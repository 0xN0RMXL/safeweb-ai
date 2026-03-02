from .base import *  # noqa: F401, F403

DEBUG = True

# Use console email backend in development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Disable throttling in development for easier testing
REST_FRAMEWORK['DEFAULT_THROTTLE_CLASSES'] = []

# Celery eager mode (runs tasks synchronously when Redis is unavailable)
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
