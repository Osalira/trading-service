from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import jwt
import logging
import os
import traceback
import socket

logger = logging.getLogger(__name__)

# Get JWT secret key from environment or use default
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'daytrading_jwt_secret_key_2024')

# Define trusted internal services
TRUSTED_SERVICES = [
    'matching-engine',
    'api-gateway'
]

# When run in docker, the hostname will resolve to the container IP
def is_request_from_trusted_service(request):
    """Check if the request is coming from a trusted internal service"""
    
    # Get client IP
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        client_ip = x_forwarded_for.split(',')[0]
    else:
        client_ip = request.META.get('REMOTE_ADDR')
    
    # Check if request is from within the Docker network
    if client_ip.startswith('172.') or client_ip.startswith('10.'):
        logger.debug(f"Request from Docker network IP: {client_ip}")
        return True
    
    # Check for specific service headers that might be set by the API gateway
    request_from = request.META.get('HTTP_X_REQUEST_FROM', '')
    if request_from in TRUSTED_SERVICES:
        logger.debug(f"Request from trusted service: {request_from}")
        return True
    
    # Check for user_id in various possible header formats
    # This is a comprehensive check for different ways the header might be passed
    has_user_id_header = (
        'HTTP_USER_ID' in request.META or 
        'user_id' in request.META or
        'USER_ID' in request.META or
        request.META.get('HTTP_USER_ID') is not None or
        request.headers.get('user_id') is not None
    )
    
    if has_user_id_header and not request.META.get('HTTP_AUTHORIZATION'):
        logger.debug(f"Request with user_id header but no auth token - treating as internal service call")
        return True
        
    return False

class CustomJWTAuthentication(BaseAuthentication):
    """
    Custom authentication class for JWT tokens provided by the auth service.
    Checks for tokens either in the Authorization header (with Bearer prefix)
    or in a separate 'token' header.
    """
    
    def authenticate(self, request):
        # First check if request is from trusted internal service
        if is_request_from_trusted_service(request):
            logger.debug("Request from trusted internal service - bypassing token authentication")
            
            # Try to extract user_id from multiple possible places, with detailed logging
            user_id = None
            
            # Check HTTP_USER_ID (Django standard format)
            if 'HTTP_USER_ID' in request.META:
                user_id = request.META.get('HTTP_USER_ID')
                logger.debug(f"Found user_id in HTTP_USER_ID header: {user_id}")
            
            # Check regular header via request.headers dict
            elif request.headers.get('user_id'):
                user_id = request.headers.get('user_id')
                logger.debug(f"Found user_id in request.headers: {user_id}")
            
            # Check direct META key (less common)
            elif 'user_id' in request.META:
                user_id = request.META.get('user_id')
                logger.debug(f"Found user_id in direct META: {user_id}")
                
            # Check in body for POST/PUT requests
            elif hasattr(request, 'data') and isinstance(request.data, dict) and 'user_id' in request.data:
                user_id = request.data.get('user_id')
                logger.debug(f"Found user_id in request.data: {user_id}")
                
            # If still no user_id found, check query parameters
            elif request.GET.get('user_id'):
                user_id = request.GET.get('user_id')
                logger.debug(f"Found user_id in query parameters: {user_id}")
            
            # Default to system user only if no user_id was found anywhere
            if user_id is None:
                user_id = '999'
                logger.warning(f"No user_id found in request, defaulting to system user: {user_id}")
            
            # Ensure user_id is treated as integer/string consistently
            try:
                user_id = str(user_id)  # Convert to string first
                logger.debug(f"Final user_id for authentication: {user_id}")
            except Exception as e:
                logger.error(f"Error converting user_id: {str(e)}")
                user_id = '999'  # Fallback to system user
            
            # Create a minimal user_info dict with just the ID
            user_info = {'id': user_id}
            
            # Set user_id directly on request for view access
            request.user_id = user_id
            
            return (None, user_info)
            
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
            # Use the user_id directly from headers if available, even without token
            # This is a fallback for internal trusted service calls
            if 'HTTP_USER_ID' in request.META or 'user_id' in request.META:
                user_id = request.META.get('HTTP_USER_ID') or request.META.get('user_id')
                if user_id:
                    logger.debug(f"Using direct user_id header for authentication: {user_id}")
                    # Create a minimal user_info dict with just the ID
                    user_info = {'id': user_id}
                    # Set user_id directly on request for view access
                    request.user_id = user_id
                    return (None, user_info)
            return None
        
        logger.debug(f"Token found (first 10 chars): {token[:10]}...")
        
        # Validate and decode token
        try:
            logger.debug(f"Attempting to decode JWT token with secret key: {JWT_SECRET_KEY[:5]}...")
            
            # Try more flexible decoding options
            decoded_token = None
            errors = []
            
            # First try the standard approach with signature verification
            try:
                decoded_token = jwt.decode(
                    token,
                    JWT_SECRET_KEY,
                    algorithms=['HS256'],
                    options={"verify_sub": False}  # Don't verify subject type
                )
                logger.debug("Successfully decoded and verified token")
            except Exception as e:
                logger.debug(f"Standard JWT decode failed: {str(e)}")
                errors.append(str(e))
                
                # Try with verify_signature=False as fallback (for development/debugging)
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
            
            logger.debug(f"Successfully decoded token, claims: {list(decoded_token.keys())}")
            
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
                # User ID - try various fields that might contain it
                if 'id' in user_info:
                    request.user_id = user_info.get('id')
                elif 'user_id' in user_info:
                    request.user_id = user_info.get('user_id')
                
                # Username
                if 'username' in user_info:
                    request.username = user_info.get('username')
                
                # Account type
                if 'account_type' in user_info:
                    request.account_type = user_info.get('account_type')
                
                # Log what we found
                logger.debug(f"Authentication successful: user_id={getattr(request, 'user_id', None)}, username={getattr(request, 'username', None)}, account_type={getattr(request, 'account_type', None)}")
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