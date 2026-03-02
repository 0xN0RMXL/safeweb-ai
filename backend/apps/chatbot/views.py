from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import ChatSession, ChatMessage
from .serializers import ChatInputSerializer, ChatSessionSerializer
from .engine import get_chat_engine


class ChatView(APIView):
    """Send a message and get an AI response."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChatInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data or {}

        message_text = data['message']
        session_id = data.get('session_id')
        scan_id = data.get('scan_id')

        # Get or create session
        session = self._get_or_create_session(request, session_id)

        # Build scan context if scan_id provided
        scan_context = ''
        if scan_id:
            scan_context = self._get_scan_context(scan_id, request.user)

        # Save user message
        ChatMessage.objects.create(
            session=session,
            role='user',
            content=message_text,
        )

        # Generate AI response
        engine = get_chat_engine()
        result = engine.generate_response(message_text, session, scan_context)

        # Save assistant message
        assistant_msg = ChatMessage.objects.create(
            session=session,
            role='assistant',
            content=result['response'],
            tokens_used=result['tokens_used'],
        )

        # Update session title from first message
        if session.title == 'New Chat':
            session.title = message_text[:50]
            session.save(update_fields=['title'])

        return Response({
            'response': result['response'],
            'session_id': str(session.id),
            'sessionId': str(session.id),
            'message_id': str(assistant_msg.id),
            'tokens_used': result['tokens_used'],
        })

    def _get_or_create_session(self, request, session_id=None):
        """Get existing session or create a new one."""
        if session_id:
            try:
                return ChatSession.objects.get(id=session_id, user=request.user)
            except ChatSession.DoesNotExist:
                pass

        # Create new session
        return ChatSession.objects.create(
            user=request.user,
            session_key=request.session.session_key or '',
        )

    def _get_scan_context(self, scan_id, user):
        """Build context string from scan results."""
        try:
            from apps.scanning.models import Scan
            scan = Scan.objects.get(id=scan_id, user=user)

            context_parts = [
                f'Target: {scan.target}',
                f'Score: {scan.score}/100' if scan.score else '',
                f'Status: {scan.status}',
            ]

            vulns = scan.vulnerabilities.all()[:10]
            if vulns:
                context_parts.append(f'Vulnerabilities found: {vulns.count()}')
                for v in vulns:
                    context_parts.append(f'- [{v.severity.upper()}] {v.name}: {v.description[:100]}')

            return '\n'.join(filter(None, context_parts))
        except Exception:
            return ''


class ChatSessionListView(APIView):
    """List user's chat sessions."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        sessions = ChatSession.objects.filter(user=request.user)[:20]
        serializer = ChatSessionSerializer(sessions, many=True)
        return Response(serializer.data)


class ChatSessionDetailView(APIView):
    """Get messages for a chat session."""
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        try:
            session = ChatSession.objects.get(id=session_id, user=request.user)
        except ChatSession.DoesNotExist:
            return Response({'detail': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = ChatSessionSerializer(session)
        return Response(serializer.data)

    def delete(self, request, session_id):
        try:
            session = ChatSession.objects.get(id=session_id, user=request.user)
            session.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except ChatSession.DoesNotExist:
            return Response({'detail': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)
