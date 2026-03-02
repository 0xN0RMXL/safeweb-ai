from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.db.models import Q
from .models import Article
from .serializers import ArticleListSerializer, ArticleDetailSerializer


class ArticleListView(APIView):
    """List published articles with search and category filtering."""
    permission_classes = [AllowAny]

    def get(self, request):
        queryset = Article.objects.filter(is_published=True)

        # Search
        search = request.query_params.get('search', '')
        if search:
            queryset = queryset.filter(
                Q(title__icontains=search) |
                Q(excerpt__icontains=search) |
                Q(content__icontains=search)
            )

        # Category filter
        category = request.query_params.get('category', '')
        if category and category != 'all':
            queryset = queryset.filter(category=category)

        articles = queryset[:20]
        serializer = ArticleListSerializer(articles, many=True)

        # Get available categories
        categories = [
            {'value': 'all', 'label': 'All Articles'},
        ]
        for value, label in Article.CATEGORY_CHOICES:
            categories.append({'value': value, 'label': label})

        return Response({
            'articles': serializer.data,
            'categories': categories,
            'total': queryset.count(),
        })


class ArticleDetailView(APIView):
    """Get a single article by slug or ID."""
    permission_classes = [AllowAny]

    def get(self, request, slug):
        try:
            article = Article.objects.get(slug=slug, is_published=True)
        except Article.DoesNotExist:
            # Try by ID
            try:
                article = Article.objects.get(id=slug, is_published=True)
            except (Article.DoesNotExist, ValueError):
                return Response(
                    {'detail': 'Article not found'},
                    status=status.HTTP_404_NOT_FOUND,
                )

        serializer = ArticleDetailSerializer(article)
        return Response(serializer.data)
