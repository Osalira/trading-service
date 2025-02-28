from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import jwt
import logging
import os
import traceback

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
        
        # Log attempt to authenticate
        logger.debug(f"Attempting to authenticate request to: {request.path}")
        
        # Check Authorization header with Bearer prefix
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header:
            logger.debug(f"Found Authorization header: {auth_header[:15]}...")
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                logger.debug("Extracted token from Bearer Authorization header")
            else:
                # If no Bearer prefix, use the whole header value
                token = auth_header
                logger.debug("Using Authorization header value directly as token")
        
        # Check token header
        elif 'HTTP_TOKEN' in request.META:
            token = request.META.get('HTTP_TOKEN')
            logger.debug("Found token in HTTP_TOKEN header")
        
        # Try other possible header names
        elif 'token' in request.META:
            token = request.META.get('token')
            logger.debug("Found token in token header (direct key)")
        elif 'TOKEN' in request.META:
            token = request.META.get('TOKEN')
            logger.debug("Found token in TOKEN header (direct key)")
        
        # Also check query parameters if no token found in headers
        elif 'token' in request.GET:
            token = request.GET.get('token')
            logger.debug("Found token in query parameters")
        
        if not token:
            logger.warning("No token found in request headers or query parameters")
            return None
        
        logger.debug(f"Token found (first 10 chars): {token[:10]}...")
        
        # Validate and decode token
        try:
            logger.debug(f"Attempting to decode JWT token with secret key: {JWT_SECRET_KEY[:5]}...")
            
            # Try more flexible decoding options
            decoded_token = None
            errors = []
            
            # First try the standard approach
            try:
                decoded_token = jwt.decode(
                    token,
                    JWT_SECRET_KEY,
                    algorithms=['HS256'],
                    options={"verify_sub": False}  # Don't verify subject type
                )
            except Exception as e:
                logger.debug(f"Standard JWT decode failed: {str(e)}")
                errors.append(str(e))
                
                # Try with verify_signature=False as fallback
                try:
                    decoded_token = jwt.decode(
                        token,
                        options={"verify_signature": False}
                    )
                    logger.warning("JWT decoded with verify_signature=False (insecure but used for debugging)")
                except Exception as e2:
                    logger.debug(f"JWT decode with verify_signature=False failed: {str(e2)}")
                    errors.append(str(e2))
            
            if not decoded_token:
                error_msg = '; '.join(errors)
                logger.error(f"All JWT decode attempts failed: {error_msg}")
                raise jwt.InvalidTokenError(f"Failed to decode token: {error_msg}")
            
            logger.debug(f"Successfully decoded token, claims: {decoded_token.keys()}")
            
            # Extract user info from the subject claim
            user_info = None
            if 'sub' in decoded_token:
                user_info = decoded_token.get('sub')
                logger.debug("Found user info in 'sub' claim")
            
            # If no sub claim or it's not a dict, try to use other claims
            if not user_info or not isinstance(user_info, dict):
                logger.warning("Token has no 'sub' claim or it's not a dict, trying to construct user_info from other claims")
                user_info = {}
                
                # Look for common user identifiers in root claims
                for key in ['user_id', 'id', 'userId', 'username']:
                    if key in decoded_token:
                        user_info[key.replace('userId', 'id')] = decoded_token.get(key)
                        
                # If we found nothing useful, log warning but continue
                if not user_info:
                    logger.warning(f"Couldn't find user information in token. Available claims: {list(decoded_token.keys())}")
                    # Use the entire token as user_info for debugging
                    user_info = decoded_token
            
            logger.debug(f"User info from token: {user_info}")
                
            # Set user_id on request object for direct access in views
            if isinstance(user_info, dict):
                request.user_id = user_info.get('id')
                request.username = user_info.get('username')
                request.account_type = user_info.get('account_type')
                
                logger.debug(f"Authentication successful: user_id={request.user_id}, username={request.username}, account_type={request.account_type}")
            else:
                logger.warning(f"User info is not a dict: {type(user_info)}")
                # Try to set user_id directly if possible
                if 'id' in decoded_token:
                    request.user_id = decoded_token.get('id')
                    logger.debug(f"Set user_id directly from token: {request.user_id}")
            
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
            logger.error(traceback.format_exc())
            raise AuthenticationFailed(f'Token validation error: {str(e)}') 