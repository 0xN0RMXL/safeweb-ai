from django.test import TestCase
from rest_framework.test import APIClient
from .engine import ChatEngine


class ChatEngineTest(TestCase):
    def test_fallback_xss(self):
        engine = ChatEngine()
        result = engine._fallback_response('What is XSS?')
        self.assertIn('Cross-Site Scripting', result['response'])
        self.assertEqual(result['tokens_used'], 0)

    def test_fallback_sqli(self):
        engine = ChatEngine()
        result = engine._fallback_response('Tell me about SQL injection')
        self.assertIn('SQL Injection', result['response'])

    def test_fallback_generic(self):
        engine = ChatEngine()
        result = engine._fallback_response('Hello')
        self.assertIn('SafeWeb AI Assistant', result['response'])


class ChatAPITest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_send_message(self):
        response = self.client.post('/api/chat/', {
            'message': 'What is XSS?',
        }, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertIn('response', response.data)
        self.assertIn('session_id', response.data)
