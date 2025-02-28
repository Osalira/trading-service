import logging
from django.conf import settings

logger = logging.getLogger(__name__)

class TokenConversionMiddleware:
    """
    Middleware to convert different token formats to a consistent format
    that Django's authentication system can understand.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        """Process the request before it reaches the view."""
        try:
            # Log all request headers for debugging
            logger.debug("Request META entries:")
            for key, value in request.META.items():
                if key.startswith('HTTP_'):
                    # Mask long values like tokens
                    value_log = value
                    if len(str(value)) > 30 and ('AUTHORIZATION' in key or 'TOKEN' in key):
                        value_log = f"{value[:10]}...{value[-10:]}"
                    logger.debug(f"  {key}: {value_log}")
            
            # Check and log the host header
            host = request.META.get('HTTP_HOST', 'unknown')
            logger.debug(f"Request host header: {host}")
            
            # Handle the "token" header format by converting it to the "Authorization" format
            if 'HTTP_TOKEN' in request.META and not request.META.get('HTTP_AUTHORIZATION'):
                token = request.META['HTTP_TOKEN']
                # Convert to Authorization: Bearer format
                request.META['HTTP_AUTHORIZATION'] = f'Bearer {token}'
                logger.debug("Converted 'token' header to 'Authorization: Bearer' format")
            
            # Handle direct 'token' metadata key if present
            if 'token' in request.META and not request.META.get('HTTP_AUTHORIZATION'):
                token = request.META['token']
                request.META['HTTP_AUTHORIZATION'] = f'Bearer {token}'
                logger.debug("Converted direct 'token' key to 'Authorization: Bearer' format")
            
            # Log the path being accessed
            logger.debug(f"Request path: {request.path}")
                
            # Log all token-related headers for debugging
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            token_header = request.META.get('HTTP_TOKEN', '')
            logger.debug(f"Request headers - Authorization: {auth_header[:20]}..., Token: {token_header[:20]}...")
        except Exception as e:
            logger.error(f"Error in TokenConversionMiddleware: {str(e)}")
        
        # Process the response as usual
        response = self.get_response(request)
        
        # Log response status for debugging
        logger.debug(f"Response status code: {response.status_code}")
        if response.status_code >= 400:
            logger.error(f"Error response: {response.status_code}")
            
        return response 