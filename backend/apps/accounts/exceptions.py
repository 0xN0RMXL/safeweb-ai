from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
import logging

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """Custom exception handler for consistent error response format."""
    response = exception_handler(exc, context)

    if response is not None:
        # Standardize error format
        if isinstance(response.data, dict):
            if 'detail' not in response.data:
                errors = {}
                detail_msg = 'Validation error.'
                for key, value in response.data.items():
                    if isinstance(value, list):
                        errors[key] = value
                    else:
                        errors[key] = [str(value)]
                response.data = {
                    'detail': detail_msg,
                    'errors': errors,
                }
        elif isinstance(response.data, list):
            response.data = {
                'detail': response.data[0] if response.data else 'An error occurred.',
                'errors': {},
            }
    else:
        logger.exception('Unhandled exception', exc_info=exc)
        response = Response(
            {'detail': 'An internal server error occurred.', 'errors': {}},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return response
