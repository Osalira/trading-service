from django.http import JsonResponse
from django.db import transaction as db_transaction
from django.db.models import F
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
import logging
import requests
import json

from trading_app.models import Stock, UserPortfolio, Wallet, StockTransaction, WalletTransaction
from serializers import (
    StockSerializer, UserPortfolioSerializer, WalletSerializer,
    StockTransactionSerializer, WalletTransactionSerializer,
    StockPriceSerializer, PortfolioResponseSerializer,
    CreateOrderSerializer, CancelOrderSerializer, AddMoneySerializer,
    WalletBalanceSerializer
)

# Configure logging
logger = logging.getLogger(__name__)

# Helper function to get user_id from request
def get_user_id(request):
    logger.debug("Attempting to get user_id from request")
    
    # First try to get user_id from our custom authentication class
    if hasattr(request, 'user_id'):
        logger.debug(f"Found user_id from request attribute: {request.user_id}")
        return request.user_id
    
    # Try to get from the user_id header
    user_id_header = request.headers.get('user_id')
    if user_id_header:
        logger.debug(f"Found user_id from header: {user_id_header}")
        return user_id_header
    
    # As a last resort, try to extract from auth object if present
    if hasattr(request, 'auth') and request.auth:
        try:
            if isinstance(request.auth, dict) and 'id' in request.auth:
                logger.debug(f"Found user_id from auth object: {request.auth.get('id')}")
                return request.auth.get('id')
        except Exception as e:
            logger.error(f"Error extracting user_id from auth object: {str(e)}")
    
    logger.warning("No user_id found in request")
    return None

# Transaction API endpoints

@api_view(['GET'])
def get_stock_prices(request):
    """Get a list of all stocks with their current prices"""
    try:
        stocks = Stock.objects.all()
        serializer = StockPriceSerializer(stocks, many=True)
        return Response(serializer.data)
    except Exception as e:
        logger.error(f"Error fetching stock prices: {str(e)}")
        return Response(
            {"error": "Failed to fetch stock prices"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_stock_portfolio(request):
    """Get the user's stock portfolio"""
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"error": "User ID not provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        portfolio = UserPortfolio.objects.filter(user_id=user_id)
        serializer = PortfolioResponseSerializer(portfolio, many=True)
        return Response(serializer.data)
    except Exception as e:
        logger.error(f"Error fetching portfolio for user {user_id}: {str(e)}")
        return Response(
            {"error": "Failed to fetch portfolio"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_stock_transactions(request):
    """Get the user's stock transaction history"""
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"error": "User ID not provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Get transaction parameters from query string
        limit = int(request.query_params.get('limit', 50))
        offset = int(request.query_params.get('offset', 0))
        
        # Get transactions
        transactions = StockTransaction.objects.filter(user_id=user_id).order_by('-timestamp')[offset:offset+limit]
        serializer = StockTransactionSerializer(transactions, many=True)
        
        # Return total count and results
        total_count = StockTransaction.objects.filter(user_id=user_id).count()
        
        return Response({
            "total_count": total_count,
            "transactions": serializer.data
        })
    except Exception as e:
        logger.error(f"Error fetching stock transactions for user {user_id}: {str(e)}")
        return Response(
            {"error": "Failed to fetch stock transactions"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_money_to_wallet(request):
    """Add money to the user's wallet"""
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"error": "User ID not provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    serializer = AddMoneySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    amount = serializer.validated_data['amount']
    
    try:
        with db_transaction.atomic():
            # Get or create wallet
            wallet, created = Wallet.objects.get_or_create(
                user_id=user_id,
                defaults={'balance': 0}
            )
            
            # Update balance
            wallet.balance = F('balance') + amount
            wallet.save()
            
            # Create wallet transaction
            transaction = WalletTransaction.objects.create(
                user_id=user_id,
                is_debit=False,  # Credit transaction
                amount=amount,
                description="Added funds to wallet"
            )
            
            # Get updated wallet
            wallet.refresh_from_db()
            
            return Response({
                "message": "Funds added successfully",
                "transaction_id": transaction.id,
                "new_balance": wallet.balance,
                "amount_added": amount
            })
    except Exception as e:
        logger.error(f"Error adding money for user {user_id}: {str(e)}")
        return Response(
            {"error": "Failed to add money to wallet"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_wallet_balance(request):
    """Get the user's wallet balance"""
    logger.info(f"get_wallet_balance endpoint accessed from {request.META.get('REMOTE_ADDR')}")
    logger.info(f"Request method: {request.method}")
    
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
    
    # Try multiple ways to get user_id
    user_id = None
    
    # Method 1: From our custom request attribute
    if hasattr(request, 'user_id'):
        user_id = request.user_id
        logger.debug(f"Found user_id from request attribute: {user_id}")
    
    # Method 2: From user_id header
    elif 'HTTP_USER_ID' in request.META:
        user_id = request.META.get('HTTP_USER_ID')
        logger.debug(f"Found user_id from HTTP_USER_ID header: {user_id}")
    
    # Method 3: From auth object
    elif hasattr(request, 'auth') and request.auth:
        try:
            if isinstance(request.auth, dict) and 'id' in request.auth:
                user_id = request.auth.get('id')
                logger.debug(f"Found user_id from auth object: {user_id}")
        except Exception as e:
            logger.error(f"Error extracting user_id from auth object: {str(e)}")
    
    if not user_id:
        logger.error("No user_id found in request")
        return Response(
            {"error": "User ID not provided or authentication failed"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        logger.info(f"Fetching wallet balance for user_id: {user_id}")
        
        # Get or create wallet
        wallet, created = Wallet.objects.get_or_create(
            user_id=user_id,
            defaults={'balance': 0}
        )
        
        if created:
            logger.info(f"Created new wallet for user {user_id} with zero balance")
        else:
            logger.info(f"Found existing wallet for user {user_id} with balance {wallet.balance}")
        
        serializer = WalletBalanceSerializer(wallet)
        return Response(serializer.data)
    except Exception as e:
        logger.error(f"Error fetching wallet balance for user {user_id}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return Response(
            {"error": f"Failed to fetch wallet balance: {str(e)}"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_wallet_transactions(request):
    """Get the user's wallet transaction history"""
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"error": "User ID not provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Get transaction parameters from query string
        limit = int(request.query_params.get('limit', 50))
        offset = int(request.query_params.get('offset', 0))
        
        # Get transactions
        transactions = WalletTransaction.objects.filter(user_id=user_id).order_by('-timestamp')[offset:offset+limit]
        serializer = WalletTransactionSerializer(transactions, many=True)
        
        # Return total count and results
        total_count = WalletTransaction.objects.filter(user_id=user_id).count()
        
        return Response({
            "total_count": total_count,
            "transactions": serializer.data
        })
    except Exception as e:
        logger.error(f"Error fetching wallet transactions for user {user_id}: {str(e)}")
        return Response(
            {"error": "Failed to fetch wallet transactions"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# Setup endpoints

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_stock(request):
    """Create a new stock (admin only)"""
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"error": "User ID not provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # In a real system, check if user is admin
    # For now, we'll accept any authenticated user
    
    serializer = StockSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        stock = serializer.save()
        return Response({
            "message": "Stock created successfully",
            "stock": StockSerializer(stock).data
        }, status=status.HTTP_201_CREATED)
    except Exception as e:
        logger.error(f"Error creating stock: {str(e)}")
        return Response(
            {"error": "Failed to create stock"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_stock_to_user(request):
    """Add stock to a user's portfolio (admin only)"""
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"error": "User ID not provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # In a real system, check if user is admin
    # For now, we'll accept any authenticated user
    
    # Validate request data
    required_fields = ['target_user_id', 'stock_id', 'quantity', 'price']
    for field in required_fields:
        if field not in request.data:
            return Response(
                {"error": f"Missing required field: {field}"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    
    target_user_id = request.data['target_user_id']
    stock_id = request.data['stock_id']
    quantity = int(request.data['quantity'])
    price = float(request.data['price'])
    
    if quantity <= 0:
        return Response(
            {"error": "Quantity must be positive"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        with db_transaction.atomic():
            # Get stock
            stock = get_object_or_404(Stock, id=stock_id)
            
            # Get or create portfolio entry
            portfolio, created = UserPortfolio.objects.get_or_create(
                user_id=target_user_id,
                stock=stock,
                defaults={'quantity': 0, 'average_price': price}
            )
            
            # Update portfolio
            if created:
                portfolio.quantity = quantity
                portfolio.average_price = price
            else:
                # Calculate new average price
                total_value = (portfolio.quantity * portfolio.average_price) + (quantity * price)
                new_quantity = portfolio.quantity + quantity
                portfolio.average_price = total_value / new_quantity
                portfolio.quantity = new_quantity
            
            portfolio.save()
            
            return Response({
                "message": "Stock added to user portfolio",
                "portfolio": UserPortfolioSerializer(portfolio).data
            })
    except Exception as e:
        logger.error(f"Error adding stock to user {target_user_id}: {str(e)}")
        return Response(
            {"error": "Failed to add stock to user"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# URL patterns (to be imported in urls.py)
# These are the URL patterns to include in your urls.py file

'''
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
]
''' 