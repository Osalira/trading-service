import logging

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
            # Handle the "token" header format by converting it to the "Authorization" format
            if 'HTTP_TOKEN' in request.META and not request.META.get('HTTP_AUTHORIZATION'):
                token = request.META['HTTP_TOKEN']
                # Convert to Authorization: Bearer format
                request.META['HTTP_AUTHORIZATION'] = f'Bearer {token}'
                logger.debug("Converted 'token' header to 'Authorization: Bearer' format")
                
            # Log all token-related headers for debugging
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            token_header = request.META.get('HTTP_TOKEN', '')
            logger.debug(f"Request headers - Authorization: {auth_header[:20]}..., Token: {token_header[:20]}...")
        except Exception as e:
            logger.error(f"Error in TokenConversionMiddleware: {str(e)}")
        
        # Process the response as usual
        response = self.get_response(request)
        return response 