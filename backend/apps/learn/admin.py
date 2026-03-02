from django.contrib import admin
from .models import Article


@admin.register(Article)
class ArticleAdmin(admin.ModelAdmin):
    list_display = ['title', 'category', 'author', 'read_time', 'is_published', 'created_at']
    list_filter = ['category', 'is_published']
    search_fields = ['title', 'excerpt']
    prepopulated_fields = {'slug': ('title',)}
