from rest_framework import serializers
from .models import Article


class ArticleListSerializer(serializers.ModelSerializer):
    """Matches the Learn.tsx article card data shape."""
    category = serializers.SerializerMethodField()
    date = serializers.DateTimeField(source='created_at', format='%Y-%m-%dT%H:%M:%S.%fZ')
    read_time = serializers.IntegerField()

    class Meta:
        model = Article
        fields = ['id', 'title', 'excerpt', 'category', 'author', 'date', 'read_time', 'image', 'slug']

    def get_category(self, obj):
        return obj.get_category_display()


class ArticleDetailSerializer(serializers.ModelSerializer):
    category = serializers.SerializerMethodField()
    date = serializers.DateTimeField(source='created_at', format='%Y-%m-%dT%H:%M:%S.%fZ')

    class Meta:
        model = Article
        fields = ['id', 'title', 'slug', 'excerpt', 'content', 'category',
                  'author', 'date', 'read_time', 'image']

    def get_category(self, obj):
        return obj.get_category_display()
