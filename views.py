from django.http import JsonResponse
from django.db import transaction as db_transaction
from django.db.models import F, Case, When, Value, IntegerField
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
import logging
import requests
import json
import jwt
from django.conf import settings

from trading_app.models import Stock, UserPortfolio, Wallet, StockTransaction, WalletTransaction, OrderStatus
from serializers import (
    StockSerializer, UserPortfolioSerializer, WalletSerializer,
    StockTransactionSerializer, WalletTransactionSerializer,
    StockPriceSerializer, PortfolioResponseSerializer,
    CreateOrderSerializer, CancelOrderSerializer, AddMoneySerializer,
    WalletBalanceSerializer, JMeterStockTransactionSerializer
)

# Configure logging
logger = logging.getLogger(__name__)

# Helper function to get user_id from request
def get_user_id(request):
    logger.debug("Attempting to get user_id from request")
    
    # First try to get user_id from query parameters
    user_id_param = request.query_params.get('user_id')
    if user_id_param:
        logger.debug(f"Found user_id from query parameter: {user_id_param}")
        return user_id_param
    
     # Try Django's META dict with HTTP_ prefix
    for meta_key in ['HTTP_USER_ID', 'HTTP_USERID']:
        if meta_key in request.META:
            user_id_meta = request.META.get(meta_key)
            logger.debug(f"Found user_id from META {meta_key}: {user_id_meta}")
            return user_id_meta


    # Second try to get user_id from our custom authentication class
    if hasattr(request, 'user_id'):
        logger.debug(f"Found user_id from request attribute: {request.user_id}")
        return request.user_id
    
    # Try to get from the user_id header - check different formats
    for header_key in ['user_id', 'User-Id', 'USER_ID', 'userId']:
        user_id_header = request.headers.get(header_key)
        if user_id_header:
            logger.debug(f"Found user_id from header {header_key}: {user_id_header}")
            return user_id_header
    
    # Check the request data for POST/PUT requests
    if hasattr(request, 'data') and isinstance(request.data, dict) and 'user_id' in request.data:
        user_id_data = request.data.get('user_id')
        logger.debug(f"Found user_id in request.data: {user_id_data}")
        return user_id_data
    
    # As a last resort, try to extract from auth object if present
    if hasattr(request, 'auth') and request.auth:
        try:
            if isinstance(request.auth, dict) and 'id' in request.auth:
                logger.debug(f"Found user_id from auth object: {request.auth.get('id')}")
                return request.auth.get('id')
        except Exception as e:
            logger.error(f"Error extracting user_id from auth object: {str(e)}")
    
    logger.warning("No user_id found in request")
    # Default to user ID 1 for testing instead of None
    logger.info("Using default user ID 1 for testing")
    return "1"

# Transaction API endpoints

@api_view(['GET'])
@permission_classes([AllowAny])
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
@permission_classes([AllowAny])
def get_stock_portfolio(request):
    """Get the user's stock portfolio (open to any authenticated user)"""
    # Check for specific user_id in query parameters
    query_user_id = request.query_params.get('user_id')
    if query_user_id:
        logger.info(f"Using user_id {query_user_id} from query parameters")
        user_id = query_user_id
    
        # Fall back to standard user_id extraction
   
    
    # Log all query parameters for debugging
    
    try:
        # Get the portfolio items
        portfolio = UserPortfolio.objects.filter(user_id=user_id)
        logger.info(f"User {user_id} portfolio has {len(portfolio)} stock items")
        for item in portfolio:
            logger.info(f"  Stock {item.stock_id} ({item.stock.symbol}): {item.quantity} shares at average price ${item.average_price}")
        
        # Get ALL pending sell orders to exclude stocks that are being sold
        # Using select_related to fetch stock information in a single query
        pending_sell_orders = StockTransaction.objects.filter(
            user_id=user_id,
            is_buy=False,  # sell orders
            status__in=['Pending', 'InProgress', 'Partially_complete']  # Explicitly use string literals for SQL query
        ).select_related('stock')
        
        # Log the query and add debugging
        query_str = str(pending_sell_orders.query)
        logger.info(f"SQL Query for pending sell orders: {query_str}")
        logger.info(f"Found {pending_sell_orders.count()} pending sell orders for user {user_id}")
        
        for order in pending_sell_orders:
            logger.info(f"  Pending sell order: Stock {order.stock_id} ({order.stock.symbol}), Quantity: {order.quantity}, Status: {order.status}")
        
        # Create a dictionary to track how many shares are pending sell for each stock
        pending_sells_by_stock = {}
        # Track transaction status for each stock
        transaction_status_by_stock = {}
        
        for order in pending_sell_orders:
            stock_id = order.stock_id
            quantity = order.quantity
            
            # Track quantities
            if stock_id in pending_sells_by_stock:
                pending_sells_by_stock[stock_id] += quantity
            else:
                pending_sells_by_stock[stock_id] = quantity
                
            # Track transaction status (prioritize PARTIALLY_COMPLETE over IN_PROGRESS over PENDING)
            if stock_id not in transaction_status_by_stock or order.status in [OrderStatus.PARTIALLY_COMPLETE, "Partially_complete"]:
                transaction_status_by_stock[stock_id] = {
                    'status': order.status,
                    'transaction_id': order.id,
                    'external_order_id': order.external_order_id
                }
        
        logger.info(f"Found {len(pending_sells_by_stock)} stocks with pending sell orders for user {user_id}")
        for stock_id, quantity in pending_sells_by_stock.items():
            status_info = transaction_status_by_stock.get(stock_id, {}).get('status', 'Unknown')
            logger.info(f"  Stock {stock_id}: {quantity} shares pending sell, status: {status_info}")
        
        # Filter portfolio items that still have available shares after pending sells
        available_portfolio = []
        
        # Debug information about portfolio processing
        logger.info("Processing portfolio items:")
        for item in portfolio:
            # Get quantity of this stock in pending sell orders
            stock_id = item.stock_id
            pending_quantity = pending_sells_by_stock.get(stock_id, 0)
            available_quantity = max(0, item.quantity - pending_quantity)
            
            # Get transaction status for this stock
            transaction_info = transaction_status_by_stock.get(stock_id, {})
            transaction_status = transaction_info.get('status')
            transaction_id = transaction_info.get('transaction_id')
            external_order_id = transaction_info.get('external_order_id')
            
            logger.info(f"  Stock {stock_id} ({item.stock.symbol}): Total: {item.quantity}, Pending sell: {pending_quantity}, Available: {available_quantity}, Status: {transaction_status}")
            
            # Only include stocks with available quantity > 0
            if available_quantity > 0:
                # Create a copy with adjusted quantity for serialization
                item_copy = UserPortfolio(
                    id=item.id,
                    user_id=item.user_id,
                    stock=item.stock,
                    quantity=available_quantity,  # Use available quantity
                    average_price=item.average_price,
                    created_at=item.created_at,
                    updated_at=item.updated_at
                )
                
                # Add status information as attributes for the serializer to use
                item_copy.has_pending_sells = pending_quantity > 0
                item_copy.pending_sell_quantity = pending_quantity
                item_copy.transaction_status = transaction_status
                item_copy.transaction_id = transaction_id
                item_copy.external_order_id = external_order_id
                
                available_portfolio.append(item_copy)
                logger.info(f"    INCLUDED in portfolio with {available_quantity} available shares, status: {transaction_status}")
            else:
                logger.info(f"    EXCLUDED from portfolio (all {item.quantity} shares are pending sell, status: {transaction_status})")
        
        # Order items by company name (Z-A)
        available_portfolio.sort(key=lambda item: item.stock.company_name, reverse=True)
        
        logger.info(f"Final available portfolio contains {len(available_portfolio)} stocks")
        
        # Explicitly return empty array when no stocks are available
        if not available_portfolio:
            logger.info(f"User {user_id} has no available stocks due to pending sell orders - returning empty array")
            return Response({'success': True, 'data': []})
        
        # Serialize the portfolio with status information
        serializer = PortfolioResponseSerializer(available_portfolio, many=True, 
                                             context={
                                                 'pending_sells': pending_sells_by_stock,
                                                 'transaction_status': transaction_status_by_stock
                                             })
        
        # Log the final serialized output
        logger.info(f"Serialized portfolio data: {serializer.data}")
        
        return Response({'success': True, 'data': serializer.data})
    except Exception as e:
        logger.error(f"Error fetching portfolio for user {user_id}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "error": f"Failed to fetch portfolio: {str(e)}"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([AllowAny])
def get_stock_transactions(request):
    """
    Get a user's stock transaction history
    """
    try:
        # Always use JMeter format for this endpoint
        use_jmeter_format = True
        logger.debug(f"Using JMeter format: {use_jmeter_format}")
        
        # Get the user ID from the request
        user_id = get_user_id(request)
        if not user_id:
            return Response({"error": "User ID is required"}, status=400)
        
        logger.debug(f"Fetching stock transactions for user ID: {user_id}")
        
        # Get pagination parameters from the query string
        limit = int(request.query_params.get('limit', 100))
        offset = int(request.query_params.get('offset', 0))
        
        # Fetch the transactions ordered by timestamp (newest first)
        transactions = StockTransaction.objects.filter(user_id=user_id).order_by('timestamp')
        logger.debug(f"Found {transactions.count()} transactions")
        
        # Apply pagination if needed
        if limit > 0:
            transactions = transactions[offset:offset+limit]
        
        # Serialize the data using JMeter format
        serialized_data = JMeterStockTransactionSerializer(transactions, many=True).data
        
        # Return just the array of transactions directly
        return Response(serialized_data)
    
    except Exception as e:
        logger.error(f"Error fetching stock transactions: {str(e)}")
        logger.error(traceback.format_exc())
        return Response({"error": "Internal server error"}, status=500)

@api_view(['POST'])
# @permission_classes([IsAuthenticated])
@permission_classes([AllowAny])
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
@permission_classes([AllowAny])  # Use AllowAny for testing
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
    
    # First check: From HTTP_USER_ID header (our custom header)
    if 'HTTP_USER_ID' in request.META:
        user_id = request.META.get('HTTP_USER_ID')
        logger.debug(f"Found user_id from HTTP_USER_ID header: {user_id}")
    
    # Second check: From direct user_id header (lowercase)
    elif 'user_id' in request.META:
        user_id = request.META.get('user_id')
        logger.debug(f"Found user_id from direct user_id header: {user_id}")
        
    # Third check: From our custom request attribute (set by authentication)
    elif hasattr(request, 'user_id'):
        user_id = request.user_id
        logger.debug(f"Found user_id from request attribute: {user_id}")
    
    # Fourth check: From auth object
    elif hasattr(request, 'auth') and request.auth:
        try:
            if isinstance(request.auth, dict):
                if 'id' in request.auth:
                    user_id = request.auth.get('id')
                    logger.debug(f"Found user_id={user_id} from auth object id field")
                elif 'user_id' in request.auth:
                    user_id = request.auth.get('user_id')
                    logger.debug(f"Found user_id={user_id} from auth object user_id field")
        except Exception as e:
            logger.error(f"Error extracting user_id from auth object: {str(e)}")
    
    # Last attempt: Try to get user info from token if we have auth token but no user_id
    if not user_id and ('HTTP_AUTHORIZATION' in request.META or 'HTTP_TOKEN' in request.META or 'token' in request.META):
        try:
            # Get token from Authorization or Token header
            token = None
            if 'HTTP_AUTHORIZATION' in request.META:
                auth_header = request.META.get('HTTP_AUTHORIZATION')
                if auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
                else:
                    token = auth_header
                logger.debug(f"Extracted token from Authorization header: {token[:10]}...")
            elif 'HTTP_TOKEN' in request.META:
                token = request.META.get('HTTP_TOKEN')
                logger.debug(f"Found token in HTTP_TOKEN header: {token[:10]}...")
            elif 'token' in request.META:
                token = request.META.get('token')
                logger.debug(f"Found token in token header: {token[:10]}...")
                
            # Try to decode token
            if token:
                # Get JWT secret key or use default
                JWT_SECRET_KEY = getattr(settings, 'JWT_SECRET_KEY', 'daytrading_jwt_secret_key_2024')
                
                # Try decoding with signature verification
                try:
                    decoded = jwt.decode(
                        token,
                        JWT_SECRET_KEY,
                        algorithms=['HS256'],
                        options={"verify_sub": False}
                    )
                    logger.debug(f"Successfully decoded token, claims: {decoded.keys()}")
                    
                    # Extract user_id from sub claim
                    if 'sub' in decoded and isinstance(decoded['sub'], dict) and 'id' in decoded['sub']:
                        user_id = decoded['sub']['id']
                        logger.debug(f"Extracted user_id={user_id} from JWT token sub.id")
                    elif 'id' in decoded:
                        user_id = decoded['id']
                        logger.debug(f"Extracted user_id={user_id} directly from token claim")
                    
                except Exception as e:
                    logger.error(f"Error decoding token: {str(e)}")
                    
                    # Try decoding without verification as fallback
                    try:
                        decoded = jwt.decode(
                            token,
                            options={"verify_signature": False}
                        )
                        logger.debug(f"Decoded token without verification, claims: {decoded.keys()}")
                        
                        # Extract user_id from sub claim
                        if 'sub' in decoded and isinstance(decoded['sub'], dict) and 'id' in decoded['sub']:
                            user_id = decoded['sub']['id']
                            logger.debug(f"Extracted user_id={user_id} from JWT token sub.id (no verification)")
                        elif 'id' in decoded:
                            user_id = decoded['id']
                            logger.debug(f"Extracted user_id={user_id} directly from token claim (no verification)")
                    except Exception as e2:
                        logger.error(f"Error decoding token without verification: {str(e2)}")
        except Exception as e:
            logger.error(f"Error attempting to extract user_id from token: {str(e)}")
    
    # If we still don't have a user_id, use a default value for testing
    if not user_id:
        logger.warning("No user_id found in request through any method, using default value '1' for testing")
        user_id = "1"  # Default value for testing only
    
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
# @permission_classes([IsAuthenticated])
@permission_classes([AllowAny])
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
@permission_classes([AllowAny])
def create_stock(request):
    """Create a new stock (open to any authenticated user)"""
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"success": False, "error": "User ID not provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Accept any authenticated user
    
    serializer = StockSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({"success": False, "error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        stock = serializer.save()
        # Get serialized data and rename 'id' to 'stock_id'
        stock_data = StockSerializer(stock).data
        stock_data['stock_id'] = stock_data.pop('id')
        
        return Response({
            'success': True,
            'data': stock_data
        }, status=status.HTTP_201_CREATED)
    except Exception as e:
        logger.error(f"Error creating stock: {str(e)}")
        return Response(
            {"success": False, "error": "Failed to create stock"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def add_stock_to_user(request):
    """Add stock to a user's portfolio (open to any authenticated user)"""
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"error": "User ID not provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Accept any authenticated user
    
    # Set defaults for missing fields
    data = request.data.copy()
    
    # Use authenticated user's ID as target_user_id if not provided
    if 'target_user_id' not in data or not data['target_user_id']:
        data['target_user_id'] = user_id
        logger.info(f"Using authenticated user's ID ({user_id}) as target_user_id")
    
    # Get latest stock if stock_id not provided
    if 'stock_id' not in data or not data['stock_id']:
        try:
            latest_stock = Stock.objects.latest('created_at')
            data['stock_id'] = latest_stock.id
            logger.info(f"Using latest stock ID: {latest_stock.id} ({latest_stock.symbol})")
        except Stock.DoesNotExist:
            return Response(
                {"error": "No stocks found in the system and no stock_id provided"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    
    # Ensure quantity is provided
    if 'quantity' not in data:
        return Response(
            {"error": "Missing required field: quantity"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    target_user_id = data['target_user_id']
    stock_id = data['stock_id']
    
    try:
        quantity = int(data['quantity'])
    except (ValueError, TypeError):
        return Response(
            {"error": "Quantity must be a valid integer"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if quantity <= 0:
        return Response(
            {"error": "Quantity must be positive"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        with db_transaction.atomic():
            # Get stock
            try:
                stock = Stock.objects.get(id=stock_id)
            except Stock.DoesNotExist:
                return Response(
                    {"error": f"Stock with ID {stock_id} not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            # Get or create portfolio entry
            portfolio, _ = UserPortfolio.objects.get_or_create(
                user_id=target_user_id,
                stock=stock,
                defaults={'quantity': 0}
            )
            
            # Just update the quantity, don't touch average_price
            portfolio.quantity += data['quantity']
            portfolio.save()
            
            return Response({
                "message": "Stock added to user portfolio",
                "portfolio": UserPortfolioSerializer(portfolio).data
            })
    except Exception as e:
        logger.error(f"Error adding stock to user {target_user_id}: {str(e)}")
        return Response(
            {"error": f"Failed to add stock to user: {str(e)}"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def process_transaction(request):
    """Process a transaction notification from the matching engine
    
    This can handle either a match notification or an order status notification:
    1. Match notification - when orders are matched, update wallet and portfolio.
    2. Order status notification - when a new order is placed, ensure it's in our system.
    """
    try:
        data = request.data
        logger.info(f"Received transaction notification: {data}")
        
        # Check if this is a new order notification
        if data.get('notification_type') == 'new_order':
            # This is an order status notification
            return process_order_notification(data)
        
        # Otherwise, process as a transaction/match notification
        buy_user_id = data.get('buy_user_id')
        sell_user_id = data.get('sell_user_id')
        stock_id = data.get('stock_id')
        quantity = data.get('quantity')
        price = data.get('price')
        timestamp = data.get('timestamp')
        buy_order_id = data.get('buy_order_id')  # External ID from matching engine
        sell_order_id = data.get('sell_order_id')  # External ID from matching engine
        
        if not all([buy_user_id, sell_user_id, stock_id, quantity, price]):
            logger.error(f"Missing required fields in transaction notification: {data}")
            return Response(
                {"success": False, "error": "Missing required fields"}, 
                status=status.HTTP_200_OK  # Return 200 to avoid retries
            )
        
        # Log the transaction details
        logger.info(f"Transaction details: Buy user: {buy_user_id}, Sell user: {sell_user_id}, Stock: {stock_id}, Qty: {quantity}, Price: {price}")
        if buy_order_id:
            logger.info(f"Buy order external ID: {buy_order_id}")
        if sell_order_id:
            logger.info(f"Sell order external ID: {sell_order_id}")
        
        with db_transaction.atomic():
            # Update the stock price to reflect the latest transaction price
            try:
                stock = Stock.objects.get(id=stock_id)
                stock.current_price = price
                stock.save()
                logger.info(f"Updated stock {stock.symbol} price to {price} based on transaction")
            except Stock.DoesNotExist:
                logger.error(f"Stock with ID {stock_id} not found when trying to update price")
            except Exception as e:
                logger.error(f"Error updating stock price: {str(e)}")
            
            # Find and update pending sell orders
            sell_orders_query = StockTransaction.objects.filter(
                user_id=sell_user_id,
                stock_id=stock_id,
                is_buy=False,  # sell orders
                status__in=[OrderStatus.PENDING, OrderStatus.IN_PROGRESS, OrderStatus.PARTIALLY_COMPLETE]
            )
            
            # If we have an external order ID, use it to find the specific order
            if sell_order_id:
                sell_orders_by_external_id = sell_orders_query.filter(external_order_id=sell_order_id)
                if sell_orders_by_external_id.exists():
                    sell_orders = sell_orders_by_external_id
                    logger.info(f"Found sell order with external ID {sell_order_id}")
                else:
                    logger.warning(f"No sell order found with external ID {sell_order_id}, falling back to chronological order")
                    sell_orders = sell_orders_query.order_by('timestamp')
            else:
                sell_orders = sell_orders_query.order_by('timestamp')
            
            if sell_orders.exists():
                logger.info(f"Found {sell_orders.count()} pending sell orders to update")
                
                # Calculate remaining quantity to process
                remaining_quantity = quantity
                
                for order in sell_orders:
                    if remaining_quantity <= 0:
                        break
                        
                    # Determine how much of this order to update
                    order_quantity = min(remaining_quantity, order.quantity)
                    remaining_quantity -= order_quantity
                    
                    # If entire order is fulfilled
                    if order_quantity >= order.quantity:
                        order.status = OrderStatus.COMPLETED
                        logger.info(f"Updated sell order {order.id} (external ID: {order.external_order_id}) to COMPLETED")
                    else:
                        # Partially fulfilled - update quantity and status
                        order.quantity -= order_quantity
                        order.status = OrderStatus.PARTIALLY_COMPLETE
                        logger.info(f"Updated sell order {order.id} (external ID: {order.external_order_id}) to PARTIALLY_COMPLETE (remaining: {order.quantity})")
                    
                    # If we received an external order ID and it's not set, update it
                    if sell_order_id and not order.external_order_id:
                        order.external_order_id = sell_order_id
                        logger.info(f"Updated sell order {order.id} with external ID {sell_order_id}")
                    
                    order.save()
                    
                    # Update user's portfolio
                    try:
                        portfolio = UserPortfolio.objects.get(user_id=sell_user_id, stock_id=stock_id)
                        portfolio.quantity -= order_quantity
                        portfolio.save()
                        logger.info(f"Updated seller portfolio: {sell_user_id}, stock: {stock_id}, new quantity: {portfolio.quantity}")
                    except UserPortfolio.DoesNotExist:
                        logger.warning(f"Portfolio not found for sell user {sell_user_id} and stock {stock_id}")
                
                if remaining_quantity > 0:
                    logger.warning(f"Not all quantity matched for sell orders. Remaining: {remaining_quantity}")
            else:
                logger.warning(f"No matching sell orders found for user {sell_user_id} and stock {stock_id}")
            
            # Find and update pending buy orders
            buy_orders_query = StockTransaction.objects.filter(
                user_id=buy_user_id,
                stock_id=stock_id,
                is_buy=True,  # buy orders
                status__in=[OrderStatus.PENDING, OrderStatus.IN_PROGRESS, OrderStatus.PARTIALLY_COMPLETE]
            )
            
            # If we have an external order ID, use it to find the specific order
            if buy_order_id:
                buy_orders_by_external_id = buy_orders_query.filter(external_order_id=buy_order_id)
                if buy_orders_by_external_id.exists():
                    buy_orders = buy_orders_by_external_id
                    logger.info(f"Found buy order with external ID {buy_order_id}")
                else:
                    logger.warning(f"No buy order found with external ID {buy_order_id}, falling back to chronological order")
                    buy_orders = buy_orders_query.order_by('timestamp')
            else:
                buy_orders = buy_orders_query.order_by('timestamp')
            
            if buy_orders.exists():
                logger.info(f"Found {buy_orders.count()} pending buy orders to update")
                
                # Calculate remaining quantity to process
                remaining_quantity = quantity
                
                for order in buy_orders:
                    if remaining_quantity <= 0:
                        break
                        
                    # Determine how much of this order to update
                    order_quantity = min(remaining_quantity, order.quantity)
                    remaining_quantity -= order_quantity
                    
                    # If entire order is fulfilled
                    if order_quantity >= order.quantity:
                        order.status = OrderStatus.COMPLETED
                        logger.info(f"Updated buy order {order.id} (external ID: {order.external_order_id}) to COMPLETED")
                    else:
                        # Partially fulfilled - update quantity and status
                        order.quantity -= order_quantity
                        order.status = OrderStatus.PARTIALLY_COMPLETE
                        logger.info(f"Updated buy order {order.id} (external ID: {order.external_order_id}) to PARTIALLY_COMPLETE (remaining: {order.quantity})")
                    
                    # If we received an external order ID and it's not set, update it
                    if buy_order_id and not order.external_order_id:
                        order.external_order_id = buy_order_id
                        logger.info(f"Updated buy order {order.id} with external ID {buy_order_id}")
                    
                    order.save()
                    
                    # Update buyer's portfolio
                    try:
                        portfolio, created = UserPortfolio.objects.get_or_create(
                            user_id=buy_user_id,
                            stock_id=stock_id,
                            defaults={
                                'quantity': 0,
                                'average_price': 0,
                                'stock': Stock.objects.get(id=stock_id)
                            }
                        )
                        
                        # Update average price
                        current_value = portfolio.quantity * portfolio.average_price
                        new_value = order_quantity * price
                        total_quantity = portfolio.quantity + order_quantity
                        
                        if total_quantity > 0:
                            portfolio.average_price = (current_value + new_value) / total_quantity
                        
                        portfolio.quantity += order_quantity
                        portfolio.save()
                        logger.info(f"Updated buyer portfolio: {buy_user_id}, stock: {stock_id}, new quantity: {portfolio.quantity}")
                    except Exception as e:
                        logger.error(f"Error updating buyer portfolio: {str(e)}")
                
                if remaining_quantity > 0:
                    logger.warning(f"Not all quantity matched for buy orders. Remaining: {remaining_quantity}")
            else:
                logger.warning(f"No matching buy orders found for user {buy_user_id} and stock {stock_id}")
        
        return Response({"success": True, "message": "Transaction processed successfully"}, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error processing transaction: {str(e)}")
        # Return 200 even on error to avoid matching engine retries
        # but include error details for debugging
        return Response(
            {"success": False, "error": f"Failed to process transaction: {str(e)}"}, 
            status=status.HTTP_200_OK
        )

def process_order_notification(data):
    """Process a notification about a new order from the matching engine"""
    logger.info(f"Processing order notification: {data}")
    
    try:
        user_id = data.get('user_id')
        stock_id = data.get('stock_id')
        is_buy = data.get('is_buy', False)
        order_type = data.get('order_type', 'LIMIT')
        order_status = data.get('status', OrderStatus.IN_PROGRESS)
        quantity = data.get('quantity', 0)
        price = data.get('price', 0)
        external_order_id = data.get('order_id')  # Updated to match the field name from matching engine
        
        # Validate required fields
        if not all([user_id, stock_id, quantity, price]):
            logger.error(f"Missing required fields in order notification: {data}")
            return Response(
                {"success": False, "error": "Missing required fields in order notification"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Try to find the stock
        try:
            stock = Stock.objects.get(id=stock_id)
        except Stock.DoesNotExist:
            logger.error(f"Stock {stock_id} not found for order notification")
            return Response(
                {"success": False, "error": f"Stock with ID {stock_id} not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if an order with this external_order_id already exists
        existing_orders = StockTransaction.objects.filter(
            external_order_id=external_order_id
        )
        
        if existing_orders.exists():
            logger.info(f"Order with external ID {external_order_id} already exists, updating status")
            # Update the existing order if needed
            for existing_order in existing_orders:
                existing_order.status = order_status
                existing_order.save()
                logger.info(f"Updated status of order {existing_order.id} to {order_status}")
        else:
            # Create a new order record with reference to the matching engine order
            transaction = StockTransaction.objects.create(
                user_id=user_id,
                stock=stock,
                is_buy=is_buy,
                order_type=order_type.upper(),
                status=order_status,
                quantity=quantity,
                price=price,
                external_order_id=external_order_id
            )
            logger.info(f"Created new order record from notification: {transaction.id}, external ID: {external_order_id}")
            
        # Return success response
        return Response({
            "success": True,
            "message": "Order notification processed successfully"
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error processing order notification: {str(e)}")
        return Response(
            {"success": False, "error": f"Error processing order notification: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def process_order_status(request):
    """Process an order status notification from the matching engine
    
    This endpoint handles order status updates from the matching engine,
    creating or updating order records in the trading service database.
    """
    logger.info(f"Received order status notification: {request.data}")
    
    try:
        # Process the notification using the existing helper function
        result = process_order_notification(request.data)
        return result
    except Exception as e:
        logger.error(f"Error processing order status: {str(e)}")
        return Response(
            {"success": False, "data": {"success": False, "error": f"Error processing order status: {str(e)}"}}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def update_stock_prices(request):
    """Update stock prices directly (for testing purposes)"""
    try:
        data = request.data
        logger.info(f"Received stock price update request: {data}")
        
        if not isinstance(data, list):
            data = [data]  # Convert single item to list
            
        updated_stocks = []
        for item in data:
            stock_id = item.get('stock_id')
            current_price = item.get('current_price')
            
            if not stock_id or current_price is None:
                continue
                
            try:
                stock = Stock.objects.get(id=stock_id)
                stock.current_price = current_price
                stock.save()
                updated_stocks.append({
                    'stock_id': stock.id,
                    'symbol': stock.symbol,
                    'stock_name': stock.company_name,
                    'current_price': stock.current_price
                })
                logger.info(f"Updated stock {stock.symbol} price to {current_price}")
            except Stock.DoesNotExist:
                logger.error(f"Stock with ID {stock_id} not found")
                
        return Response({
            "success": True,
            "message": f"Updated {len(updated_stocks)} stock prices",
            "data": updated_stocks
        })
    except Exception as e:
        logger.error(f"Error updating stock prices: {str(e)}")
        return Response(
            {"success": False, "error": f"Failed to update stock prices: {str(e)}"},
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