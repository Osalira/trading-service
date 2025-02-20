import json
import logging
from django.http import JsonResponse
from rest_framework import status

logger = logging.getLogger(__name__)

class RequestResponseMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Process request
        logger.info("=== Request Processing Start ===")
        logger.debug(f"Request path: {request.path}")
        logger.debug(f"Request method: {request.method}")
        logger.debug(f"Request content type: {request.content_type}")
        logger.debug(f"Request headers: {dict(request.headers)}")
        
        try:
            if request.content_type == 'application/json' and request.body:
                body = json.loads(request.body)
                logger.debug(f"Request body: {body}")
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in request body: {str(e)}")
            return JsonResponse({
                'success': False,
                'data': {
                    'error': 'Invalid JSON in request body'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get response
        response = self.get_response(request)
        
        logger.debug(f"Response status: {response.status_code}")
        if hasattr(response, 'content'):
            try:
                content = json.loads(response.content)
                logger.debug(f"Response content: {content}")
                
                # Skip middleware processing for non-API endpoints
                if not request.path.startswith('/api/'):
                    return response
                
                # Ensure response follows standard format
                if isinstance(content, dict):
                    if 'success' not in content:
                        content = {
                            'success': response.status_code < 400,
                            'data': content
                        }
                        response.content = json.dumps(content)
                else:
                    response.content = json.dumps({
                        'success': response.status_code < 400,
                        'data': content
                    })
                
            except json.JSONDecodeError:
                # Response is not JSON, leave it unchanged
                pass
        
        logger.info("=== Request Processing End ===")
        return response

    def process_exception(self, request, exception):
        """Handle uncaught exceptions"""
        logger.error(f"Uncaught exception in request: {str(exception)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'data': {
                'error': 'An unexpected error occurred'
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 