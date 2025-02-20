from rest_framework import authentication
from rest_framework import exceptions
from rest_framework_simplejwt.tokens import AccessToken
from django.conf import settings
import jwt
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class SimpleUser:
    def __init__(self, payload):
        self.payload = payload
        self.is_authenticated = True
        self.id = payload.get('user_id')
        self.user_id = payload.get('user_id')
        self.account_type = payload.get('account_type')
        self.name = payload.get('name')

class JWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            logger.warning("No Authorization header found in request")
            return None

        try:
            token = auth_header.split(' ')[1]
            logger.debug(f"Attempting to decode JWT token with length: {len(token)}")
            logger.debug(f"Using JWT secret key with length: {len(settings.SIMPLE_JWT['SIGNING_KEY'])}")
            
            payload = jwt.decode(
                token,
                settings.SIMPLE_JWT['SIGNING_KEY'],
                algorithms=['HS256']
            )
            logger.info(f"Successfully decoded JWT token for user_id: {payload.get('user_id')}")
            
            # Create a simple user object that has the required attributes
            user = SimpleUser(payload)
            return (user, None)
            
        except jwt.ExpiredSignatureError:
            logger.error("Token has expired")
            raise exceptions.AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {str(e)}")
            raise exceptions.AuthenticationFailed(f'Invalid token: {str(e)}')
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            raise exceptions.AuthenticationFailed('Authentication failed')

    def authenticate_header(self, request):
        return 'Bearer' 