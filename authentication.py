from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
import jwt
import logging
import os

logger = logging.getLogger(__name__)

# Get JWT secret key from environment or use default
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'daytrading_jwt_secret_key_2024')

class CustomJWTAuthentication(BaseAuthentication):
    """
    Custom authentication class for JWT tokens provided by the auth service.
    Checks for tokens either in the Authorization header (with Bearer prefix)
    or in a separate 'token' header.
    """
    
    def authenticate(self, request):
        # Extract token from request headers
        token = None
        
        # Check Authorization header with Bearer prefix
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        # Check token header
        elif 'HTTP_TOKEN' in request.META:
            token = request.META.get('HTTP_TOKEN')
        
        if not token:
            return None
        
        # Validate and decode token
        try:
            decoded_token = jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=['HS256'],
                options={"verify_sub": False}  # Don't verify subject type
            )
            
            # Extract user info from the subject claim
            user_info = decoded_token.get('sub')
            if not user_info:
                raise AuthenticationFailed('Token missing user information')
                
            # Set user_id on request object for direct access in views
            request.user_id = user_info.get('id')
            request.username = user_info.get('username')
            request.account_type = user_info.get('account_type')
            
            # Return None for user since we're not using Django's user model
            # Return user_info as auth object to be accessible in the view
            return (None, user_info)
            
        except jwt.ExpiredSignatureError:
            logger.warning('Token has expired')
            raise AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError as e:
            logger.warning(f'Invalid token: {str(e)}')
            raise AuthenticationFailed(f'Invalid token: {str(e)}')
        except Exception as e:
            logger.error(f'Token validation error: {str(e)}')
            raise AuthenticationFailed(f'Token validation error: {str(e)}') 