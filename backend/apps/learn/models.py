import uuid
from django.db import models


class Article(models.Model):
    """Learning center articles about cybersecurity topics."""
    CATEGORY_CHOICES = [
        ('injection', 'Injection Attacks'),
        ('xss', 'XSS'),
        ('best_practices', 'Best Practices'),
        ('api_security', 'API Security'),
        ('authentication', 'Authentication'),
        ('security_headers', 'Security Headers'),
        ('access_control', 'Access Control'),
        ('cryptography', 'Cryptography'),
        ('network_security', 'Network Security'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=300)
    slug = models.SlugField(max_length=300, unique=True)
    excerpt = models.TextField(max_length=500)
    content = models.TextField()
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    author = models.CharField(max_length=100, default='Security Team')
    read_time = models.IntegerField(default=5, help_text='Estimated reading time in minutes')
    image = models.URLField(blank=True, null=True)
    is_published = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title
