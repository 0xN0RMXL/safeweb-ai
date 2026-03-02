from django.test import TestCase
from rest_framework.test import APIClient  # type: ignore[import-untyped]
from rest_framework import status  # type: ignore[import-untyped]
from .models import User, APIKey


class AuthTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_data = {
            'name': 'Test User',
            'email': 'test@example.com',
            'password': 'TestP@ss1',
            'confirmPassword': 'TestP@ss1',
        }

    def test_register_success(self):
        response = self.client.post('/api/auth/register/', self.register_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('tokens', response.data)  # type: ignore[union-attr]
        self.assertEqual(response.data['user']['email'], 'test@example.com')  # type: ignore[union-attr]

    def test_register_duplicate_email(self):
        self.client.post('/api/auth/register/', self.register_data, format='json')
        response = self.client.post('/api/auth/register/', self.register_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_weak_password(self):
        data = {**self.register_data, 'password': 'weak', 'confirmPassword': 'weak'}
        response = self.client.post('/api/auth/register/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_success(self):
        self.client.post('/api/auth/register/', self.register_data, format='json')
        response = self.client.post('/api/auth/login/', {
            'email': 'test@example.com',
            'password': 'TestP@ss1',
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('tokens', response.data)  # type: ignore[union-attr]

    def test_login_invalid_credentials(self):
        response = self.client.post('/api/auth/login/', {
            'email': 'test@example.com',
            'password': 'WrongP@ss1',
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_authenticated(self):
        # Register and get token
        resp = self.client.post('/api/auth/register/', self.register_data, format='json')
        token = resp.data['tokens']['access']  # type: ignore[union-attr]
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')  # type: ignore[attr-defined]
        response = self.client.get('/api/auth/verify/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user']['email'], 'test@example.com')  # type: ignore[union-attr]

    def test_verify_unauthenticated(self):
        response = self.client.get('/api/auth/verify/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class ProfileTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='profile@example.com',
            username='profile@example.com',
            name='Profile User',
            password='TestP@ss1',
        )
        from rest_framework_simplejwt.tokens import RefreshToken  # type: ignore[import-untyped]
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')  # type: ignore[attr-defined]

    def test_get_profile(self):
        response = self.client.get('/api/user/profile/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'profile@example.com')  # type: ignore[union-attr]

    def test_update_profile(self):
        response = self.client.put('/api/user/profile/', {
            'name': 'Updated Name',
            'company': 'Test Corp',
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Updated Name')  # type: ignore[union-attr]

    def test_api_key_create(self):
        response = self.client.post('/api/user/profile/api-keys/', {
            'name': 'Test Key',
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('key', response.data)  # type: ignore[union-attr]

    def test_api_key_list(self):
        self.client.post('/api/user/profile/api-keys/', {'name': 'Key 1'}, format='json')
        response = self.client.get('/api/user/profile/api-keys/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # type: ignore[union-attr, arg-type]
