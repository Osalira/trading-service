from django.urls import path
from views import (
    get_stock_prices,
    get_stock_portfolio,
    get_stock_transactions,
    add_money_to_wallet,
    get_wallet_balance,
    get_wallet_transactions,
    create_stock,
    add_stock_to_user
)

# Add a debug view to help troubleshoot
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
import logging

@api_view(['GET', 'POST'])
@permission_classes([AllowAny])  # Explicitly allow any request, no authentication needed
def debug_auth(request):
    """Debugging endpoint to help troubleshoot authentication issues"""
    from django.conf import settings
    import json
    import traceback
    import jwt
    import os
    
    logger = logging.getLogger(__name__)
    
    # Log that this endpoint was hit
    logger.info(f"Debug auth endpoint accessed from {request.META.get('REMOTE_ADDR')}")
    logger.info(f"Request method: {request.method}")
    
    try:
        # Log all headers for debugging
        logger.debug("Request headers:")
        for key, value in request.META.items():
            if key.startswith('HTTP_'):
                # Mask token values
                if 'AUTHORIZATION' in key or 'TOKEN' in key:
                    if isinstance(value, str) and len(value) > 20:
                        logger.debug(f"  {key}: {value[:10]}...{value[-10:]}")
                    else:
                        logger.debug(f"  {key}: {value}")
                else:
                    logger.debug(f"  {key}: {value}")
        
        response_data = {
            "message": "Debug authentication information",
            "headers": {},
            "auth": {},
            "token_analysis": {},
            "request_info": {
                "method": request.method,
                "path": request.path,
                "query_params": dict(request.GET),
                "content_type": request.content_type,
                "remote_addr": request.META.get('REMOTE_ADDR'),
                "server_name": request.META.get('SERVER_NAME'),
                "server_port": request.META.get('SERVER_PORT'),
            },
            "settings": {
                "auth_classes": str(settings.REST_FRAMEWORK.get('DEFAULT_AUTHENTICATION_CLASSES', [])),
                "jwt_settings": str(getattr(settings, 'SIMPLE_JWT', {})),
                "jwt_secret_key": settings.JWT_SECRET_KEY[:5] + "..." if hasattr(settings, 'JWT_SECRET_KEY') else None,
            }
        }
        
        # Add all headers to response
        for key, value in request.META.items():
            if key.startswith('HTTP_'):
                header_name = key[5:].replace('_', '-').title()
                # Mask token values
                if 'AUTHORIZATION' in key or 'TOKEN' in key:
                    if isinstance(value, str) and len(value) > 20:
                        value = f"{value[:10]}...{value[-10:]}"
                response_data['headers'][header_name] = value
        
        # Add authentication info
        if hasattr(request, 'user_id'):
            response_data['auth']['user_id'] = request.user_id
        if hasattr(request, 'username'):
            response_data['auth']['username'] = request.username
        if hasattr(request, 'account_type'):
            response_data['auth']['account_type'] = request.account_type
        
        # Try to analyze tokens in the request
        response_data['token_analysis'] = analyze_tokens(request)
            
        # Include body content if it's a POST request
        if request.method == 'POST':
            try:
                if request.content_type == 'application/json':
                    try:
                        response_data['request_info']['body'] = json.loads(request.body)
                    except json.JSONDecodeError as e:
                        response_data['request_info']['body_error'] = f"JSON parse error: {str(e)}"
                        response_data['request_info']['raw_body'] = request.body.decode('utf-8', errors='replace')[:200]
                else:
                    response_data['request_info']['body'] = request.POST.dict()
            except Exception as e:
                logger.warning(f"Could not parse request body: {str(e)}")
                response_data['request_info']['body_error'] = str(e)
                response_data['request_info']['raw_body'] = request.body.decode('utf-8', errors='replace')[:200]
        
        return JsonResponse(response_data)
    
    except Exception as e:
        logger.error(f"Error in debug_auth: {str(e)}")
        logger.error(traceback.format_exc())
        return JsonResponse({
            "error": str(e),
            "traceback": traceback.format_exc(),
            "message": "Error occurred in debug endpoint"
        }, status=500)

def analyze_tokens(request):
    """Helper function to analyze tokens in the request and provide detailed information"""
    import jwt
    import os
    
    logger = logging.getLogger(__name__)
    
    # Get JWT secret key from environment or use default
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'daytrading_jwt_secret_key_2024')
    
    results = {
        "tokens_found": False,
        "token_sources": [],
        "decode_attempts": []
    }
    
    # Look for tokens in various places
    token_sources = [
        ('Authorization header', request.META.get('HTTP_AUTHORIZATION')),
        ('Token header', request.META.get('HTTP_TOKEN')),
        ('Direct token key', request.META.get('token')),
        ('Direct TOKEN key', request.META.get('TOKEN')),
        ('Query parameter', request.GET.get('token'))
    ]
    
    for source_name, token_value in token_sources:
        if not token_value:
            continue
            
        # We found a potential token
        results['tokens_found'] = True
        
        # Extract the token from Bearer format if needed
        token = token_value
        if source_name == 'Authorization header' and token_value.startswith('Bearer '):
            token = token_value.split(' ')[1]
            source_name = 'Bearer Authorization header'
            
        # Add token source with masked value
        if len(token) > 20:
            masked_token = f"{token[:10]}...{token[-10:]}"
        else:
            masked_token = token
            
        results['token_sources'].append({
            "source": source_name,
            "masked_value": masked_token,
            "token_length": len(token)
        })
        
        # Try to decode the token
        decode_result = {
            "source": source_name,
            "token_prefix": token[:10] if len(token) > 10 else token,
            "decode_attempts": []
        }
        
        # Attempt 1: Standard decode with secret
        try:
            decoded = jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=['HS256'],
                options={"verify_sub": False}
            )
            
            decode_result["decode_attempts"].append({
                "method": "Standard JWT decode",
                "success": True,
                "claims": {k: v for k, v in decoded.items() if k != 'sub'},
                "subject": decoded.get('sub') if isinstance(decoded.get('sub'), dict) else None
            })
        except Exception as e:
            decode_result["decode_attempts"].append({
                "method": "Standard JWT decode",
                "success": False,
                "error": str(e)
            })
            
            # Attempt 2: Unsecured decode (for debugging only)
            try:
                decoded = jwt.decode(
                    token,
                    options={"verify_signature": False}
                )
                
                decode_result["decode_attempts"].append({
                    "method": "Unsecured JWT decode",
                    "success": True,
                    "claims": {k: v for k, v in decoded.items() if k != 'sub'},
                    "subject": decoded.get('sub') if isinstance(decoded.get('sub'), dict) else None,
                    "warning": "Token decoded without signature verification (insecure)"
                })
            except Exception as e2:
                decode_result["decode_attempts"].append({
                    "method": "Unsecured JWT decode",
                    "success": False,
                    "error": str(e2)
                })
        
        results["decode_attempts"].append(decode_result)
    
    return results

urlpatterns = [
    # Transaction endpoints
    path('api/transaction/getStockPrices', get_stock_prices, name='get_stock_prices'),
    path('api/transaction/getStockPortfolio', get_stock_portfolio, name='get_stock_portfolio'),
    path('api/transaction/getStockTransactions', get_stock_transactions, name='get_stock_transactions'),
    path('api/transaction/addMoneyToWallet', add_money_to_wallet, name='add_money_to_wallet'),
    path('api/transaction/getWalletBalance', get_wallet_balance, name='get_wallet_balance'),
    path('api/transaction/getWalletTransactions', get_wallet_transactions, name='get_wallet_transactions'),
    
    # Setup endpoints
    path('api/setup/createStock', create_stock, name='create_stock'),
    path('api/setup/addStockToUser', add_stock_to_user, name='add_stock_to_user'),
    
    # Debug endpoints - no authentication required
    path('api/debug/auth', debug_auth, name='debug_auth'),
    
    # Alternative paths (with trailing slashes) for Django handling
    path('api/transaction/getStockPrices/', get_stock_prices, name='get_stock_prices_slash'),
    path('api/transaction/getStockPortfolio/', get_stock_portfolio, name='get_stock_portfolio_slash'),
    path('api/transaction/getStockTransactions/', get_stock_transactions, name='get_stock_transactions_slash'),
    path('api/transaction/addMoneyToWallet/', add_money_to_wallet, name='add_money_to_wallet_slash'),
    path('api/transaction/getWalletBalance/', get_wallet_balance, name='get_wallet_balance_slash'),
    path('api/transaction/getWalletTransactions/', get_wallet_transactions, name='get_wallet_transactions_slash'),
    path('api/debug/auth/', debug_auth, name='debug_auth_slash'),
] 