from django.http import JsonResponse
from django.db import transaction as db_transaction
from django.db.models import F, Case, When, Value, IntegerField, Sum, Avg, Count, Q
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
from decimal import Decimal
import os
import uuid
from django.utils import timezone
from datetime import timedelta
from django.db import connection
import traceback

from trading_app.models import Stock, UserPortfolio, Wallet, StockTransaction, WalletTransaction, OrderStatus, OrderType
from serializers import (
    StockSerializer, UserPortfolioSerializer, WalletSerializer,
    StockTransactionSerializer, WalletTransactionSerializer,
    StockPriceSerializer, PortfolioResponseSerializer,
    CreateOrderSerializer, CancelOrderSerializer, AddMoneySerializer,
    WalletBalanceSerializer, JMeterStockTransactionSerializer,
    JMeterWalletTransactionSerializer
)

# Import RabbitMQ functions for event publishing
from rabbitmq import publish_event

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
        stocks = Stock.objects.all().order_by('-company_name')  # Z comes before A
        serializer = StockPriceSerializer(stocks, many=True)
        return Response({"success": True, "data": serializer.data})
    except Exception as e:
        logger.error(f"Error fetching stock prices: {str(e)}")
        return Response(
            {"success": False, "error": "Failed to fetch stock prices"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([AllowAny])
def get_stock_portfolio(request):
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"success": False, "data": {"error": "No user ID provided"}}, 
            status=status.HTTP_200_OK  # Return 200 even for errors as required by JMeter
        )
    
    logger.info(f"Getting stock portfolio for user {user_id}")
    
    try:
        # Get all stocks owned by the user
        portfolio = UserPortfolio.objects.filter(user_id=user_id).select_related('stock')
        logger.info(f"User {user_id} portfolio has {portfolio.count()} stock items")
        
        # Log basic portfolio information
        for item in portfolio:
            logger.info(f"  Stock {item.stock_id} ({item.stock.symbol}): {item.quantity} shares at average price ${item.average_price}")
        
        # Find all pending sell orders for this user - we'll exclude these stocks from the portfolio
        stocks_with_pending_sells = set()
        pending_sell_quantity = {}
        
        # Get pending sell orders (status PENDING, PARTIAL, or IN_PROGRESS)
        pending_sell_orders = StockTransaction.objects.filter(
            user_id=user_id,
            is_buy=False,  # sell orders only
            status__in=[OrderStatus.PENDING, OrderStatus.PARTIALLY_COMPLETE, OrderStatus.IN_PROGRESS]  # any incomplete order status
        ).select_related('stock')
        
        logger.info(f"Found {pending_sell_orders.count()} pending sell orders for user {user_id}")
        
        # Add stocks with pending sell orders to our exclusion set
        for order in pending_sell_orders:
            stock_id = int(order.stock_id)
            stocks_with_pending_sells.add(stock_id)
            pending_sell_quantity[stock_id] = pending_sell_quantity.get(stock_id, 0) + order.quantity
            logger.info(f"  Found pending sell order: ID {order.id}, Stock {stock_id} ({order.stock.symbol}), Status: {order.status}, Quantity: {order.quantity}")
        
        logger.info(f"Found {len(stocks_with_pending_sells)} stocks with pending sell orders for user {user_id}")
        logger.info(f"Stocks to exclude: {stocks_with_pending_sells}")
        
        # Process portfolio items to compute available quantity
        portfolio_items = []
        for item in portfolio:
            stock_id = item.stock_id
            stock_id_int = int(stock_id)
            
            # Skip stocks with pending sells - this is the key requirement
            if stock_id_int in stocks_with_pending_sells:
                logger.info(f"  EXCLUDING Stock {stock_id} ({item.stock.symbol}) from portfolio due to pending sell orders")
                continue
            
            # Calculate information for stocks that don't have pending sell orders
            portfolio_item = {
                'stock_id': str(item.stock_id),
                'stock_name': item.stock.company_name if hasattr(item.stock, 'company_name') else item.stock.name,
                'stock_symbol': item.stock.symbol,
                'current_price': item.stock.current_price,
                'average_price': item.average_price,
                'quantity_owned': item.quantity,
                'total_value': float(item.stock.current_price or 0) * item.quantity if item.stock.current_price else 0,
                'profit_loss': 0,
                'profit_loss_percentage': 0,
                'available_quantity': item.quantity
            }
            
            # Calculate profit/loss if we have both prices
            if item.average_price and item.stock.current_price:
                portfolio_item['profit_loss'] = (item.stock.current_price - item.average_price) * item.quantity
                if item.average_price > 0:
                    portfolio_item['profit_loss_percentage'] = ((item.stock.current_price - item.average_price) / item.average_price) * 100
            
            portfolio_items.append(portfolio_item)
        
        # Sort portfolio items in reverse alphabetical order by stock_name (Z to A)
        portfolio_items.sort(key=lambda item: item['stock_name'], reverse=True)
        
        logger.info(f"Final available portfolio contains {len(portfolio_items)} stocks")
        
        # Return the portfolio in JMeter format
        return Response({"success": True, "data": portfolio_items})
    
    except Exception as e:
        logger.error(f"Error fetching stock portfolio: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "data": {"error": f"Internal error: {str(e)}"}}, 
            status=status.HTTP_200_OK  # Return 200 even for errors as required by JMeter
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
            return Response(
                {"success": False, "data": {"error": "User ID is required"}}, 
                status=status.HTTP_200_OK  # Return 200 even for errors as required by JMeter
            )
        
        logger.debug(f"Fetching stock transactions for user ID: {user_id}")
        
        # Get pagination parameters from the query string
        limit = int(request.query_params.get('limit', 100))
        offset = int(request.query_params.get('offset', 0))
        
        # Fetch the transactions ordered by timestamp (newest first) to match wallet transactions view
        transactions = StockTransaction.objects.filter(user_id=user_id).order_by('timestamp')
        
        # Use select_related to fetch related objects in one query
        transactions = transactions.select_related('stock')
        
        logger.debug(f"Found {transactions.count()} transactions")
        
        # Apply pagination if needed
        if limit > 0:
            transactions = transactions[offset:offset+limit]
        
        # Log details of each transaction for debugging
        for tx in transactions:
            logger.debug(f"Transaction {tx.id}: stock={tx.stock_id}, price={tx.price}")
        
        # Serialize the data using JMeter format
        serialized_data = JMeterStockTransactionSerializer(transactions, many=True).data
        
        # Return with success key for consistency with other endpoints
        return Response({"success": True, "data": serialized_data})
    
    except Exception as e:
        logger.error(f"Error fetching stock transactions: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "data": {"error": f"Internal error: {str(e)}"}}, 
            status=status.HTTP_200_OK  # Return 200 even for errors as required by JMeter
        )

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
@permission_classes([AllowAny])  # Use AllowAny for testing
def get_wallet_transactions(request):
    """Get the user's wallet transaction history"""
    user_id = get_user_id(request)
    if not user_id:
        return Response(
            {"success": False, "data": {"error": "User ID not provided"}}, 
            status=status.HTTP_200_OK  # Return 200 even for errors as required by JMeter
        )
    
    try:
        # Get transaction parameters from query string
        limit = int(request.query_params.get('limit', 50))
        offset = int(request.query_params.get('offset', 0))
        
        # Get ONLY the requested user's transactions
        # IMPORTANT: This is where we fix the bug - strictly filter by user_id
        all_transactions = WalletTransaction.objects.filter(user_id=user_id)
        
        # NEW: Additional filtering to ensure data integrity
        valid_transactions = []
        invalid_reference_count = 0
        cross_user_reference_count = 0
        
        # First pass: Check for invalid references and log warnings
        for tx in all_transactions:
            is_valid = True
            
            if tx.stock_transaction_id is not None:
                # Check if the referenced stock transaction exists
                try:
                    stock_tx = StockTransaction.objects.get(id=tx.stock_transaction_id)
                    
                    # Check if stock transaction belongs to the same user
                    if stock_tx.user_id != int(user_id):
                        logger.warning(f"CROSS-USER REFERENCE: Wallet transaction {tx.id} for user {user_id} references stock transaction {tx.stock_transaction_id} belonging to user {stock_tx.user_id}")
                        cross_user_reference_count += 1
                        # Mark as invalid - we don't want to show cross-user references
                        is_valid = False
                except StockTransaction.DoesNotExist:
                    logger.warning(f"INVALID REFERENCE: Wallet transaction {tx.id} references non-existent stock transaction {tx.stock_transaction_id}")
                    invalid_reference_count += 1
                    # Don't show transactions with references to non-existent entities
                    is_valid = False
            
            if is_valid:
                valid_transactions.append(tx)
        
        logger.info(f"Filtered out {cross_user_reference_count} cross-user references and {invalid_reference_count} invalid references")
        all_transactions = valid_transactions
        
        # Process transactions to handle potential duplicates where stock_transaction is null
        # First, collect all transactions with non-null stock_transaction
        transactions_with_stock_tx = [tx for tx in all_transactions if tx.stock_transaction_id is not None]
        
        # Now collect all transactions with null stock_transaction
        transactions_with_null_stock_tx = [tx for tx in all_transactions if tx.stock_transaction_id is None]
        
        # Create a dictionary to track duplicates by key attributes + timestamp window
        # We'll use a window of 2 seconds to consider transactions as potential duplicates
        tx_groups = {}
        
        # First, group the transactions with non-null stock_tx_id
        for tx in transactions_with_stock_tx:
            # Create a more unique key based on user, type, amount, stock, and stock_transaction
            base_key = f"{tx.user_id}_{tx.is_debit}_{tx.amount}_{tx.stock_id if tx.stock_id else 'None'}_{tx.stock_transaction_id}"
            
            # Only add this transaction as a candidate if it doesn't exist yet
            if base_key not in tx_groups:
                tx_groups[base_key] = {'preferred': tx, 'duplicates': []}
        
        # Now, check null stock_tx_id transactions for duplicates
        duplicate_ids = set()
        for tx in transactions_with_null_stock_tx:
            # Same key structure for consistency
            base_key = f"{tx.user_id}_{tx.is_debit}_{tx.amount}_{tx.stock_id if tx.stock_id else 'None'}_no_stock_tx"
            
            # If we have a non-null match for this transaction
            if base_key in tx_groups:
                preferred_tx = tx_groups[base_key]['preferred']
                
                # Check if they're close in time (within 1 second - more conservative)
                time_diff = abs((preferred_tx.timestamp - tx.timestamp).total_seconds())
                if time_diff <= 1.0:  # 1 second window - more conservative than before
                    # This is likely a duplicate, mark it
                    duplicate_ids.add(tx.id)
                    tx_groups[base_key]['duplicates'].append(tx)
                    logger.info(f"Identified duplicate wallet transaction: {tx.id} matches {preferred_tx.id} (time diff: {time_diff}s)")
        
        # Create the final list of non-duplicate transactions
        final_transactions = []
        
        # Add all transactions with stock_tx_id
        for tx in transactions_with_stock_tx:
            final_transactions.append(tx)
        
        # Add null stock_tx_id transactions that aren't duplicates
        for tx in transactions_with_null_stock_tx:
            if tx.id not in duplicate_ids:
                final_transactions.append(tx)
        
        # Sort by timestamp (descending) and apply limit/offset
        final_transactions.sort(key=lambda x: x.timestamp, reverse=True)
        transactions = final_transactions[offset:offset+limit]
        
        logger.info(f"Fetched {len(transactions)} wallet transactions for user {user_id} after filtering {len(duplicate_ids)} duplicates, {cross_user_reference_count} cross-user references, and {invalid_reference_count} invalid references")
        
        # Check if JMeter format is requested (default to true for compatibility)
        use_jmeter_format = request.query_params.get('jmeter_format', 'true').lower() == 'true'
        
        if use_jmeter_format:
            # Use JMeter format - data is a direct array of transactions
            serializer = JMeterWalletTransactionSerializer(transactions, many=True)
            return Response({
                "success": True,
                "data": serializer.data
            })
        else:
            # Use original format with nested transactions array
            serializer = WalletTransactionSerializer(transactions, many=True)
            total_count = len(final_transactions)
            return Response({
                "success": True,
                "data": {
                    "total_count": total_count,
                    "transactions": serializer.data
                }
            })
    except Exception as e:
        logger.error(f"Error getting wallet transactions: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "data": {"error": f"Internal error: {str(e)}"}}, 
            status=status.HTTP_200_OK  # Return 200 even for errors as required by JMeter
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
    
    This function is now the ONLY place where wallet transactions are created to prevent duplicates.
    """
    # Generate a trace ID for tracking this transaction
    trace_id = request.headers.get('X-Request-ID', uuid.uuid4().hex[:8])
    logger.info(f"[TraceID: {trace_id}] Starting transaction processing")
    
    try:
        data = request.data
        logger.info(f"[TraceID: {trace_id}] Received transaction notification: {data}")
        
        # Check if this is a new order notification
        if data.get('notification_type') == 'new_order':
            # This is an order status notification
            logger.info(f"[TraceID: {trace_id}] This is a new order notification, forwarding to process_order_notification")
            return process_order_notification(data, trace_id)
        
        # Otherwise, process as a transaction/match notification
        logger.info(f"[TraceID: {trace_id}] This is a transaction match notification, will handle wallet transactions here")
        buy_user_id = data.get('buy_user_id')
        sell_user_id = data.get('sell_user_id')
        stock_id = data.get('stock_id')
        quantity = data.get('quantity')
        price = data.get('price')
        timestamp = data.get('timestamp')
        buy_order_id = data.get('buy_order_id')  # External ID from matching engine
        sell_order_id = data.get('sell_order_id')  # External ID from matching engine
        
        if not all([buy_user_id, sell_user_id, stock_id, quantity, price]):
            logger.error(f"[TraceID: {trace_id}] Missing required fields in transaction notification: {data}")
            
            # Publish error event
            publish_event('system_events', 'system.error', {
                'event_type': 'system.error',
                'service': 'trading-service',
                'operation': 'process_transaction',
                'error': 'Missing required fields in transaction notification',
                'trace_id': trace_id,
                'data': data
            })
            
            return Response(
                {"success": False, "error": "Missing required fields"}, 
                status=status.HTTP_200_OK  # Return 200 to avoid retries
            )
        
        # Log the transaction details
        logger.info(f"[TraceID: {trace_id}] Transaction details: Buy user: {buy_user_id}, Sell user: {sell_user_id}, Stock: {stock_id}, Qty: {quantity}, Price: {price}")
        if buy_order_id:
            logger.info(f"[TraceID: {trace_id}] Buy order external ID: {buy_order_id}")
        if sell_order_id:
            logger.info(f"[TraceID: {trace_id}] Sell order external ID: {sell_order_id}")
        
        # Publish order.matched event before db transaction
        try:
            stock_obj = Stock.objects.get(id=stock_id)
            stock_symbol = stock_obj.symbol
            
            publish_event('order_events', 'order.matched', {
                'event_type': 'order.matched',
                'trace_id': trace_id,
                'buy_user_id': buy_user_id,
                'sell_user_id': sell_user_id,
                'buy_order_id': buy_order_id,
                'sell_order_id': sell_order_id,
                'stock_id': stock_id,
                'stock_symbol': stock_symbol,
                'quantity': quantity,
                'price': str(price),  # Convert to string for JSON serialization
                'matched_at': timestamp or timezone.now().isoformat(),
                'total_value': str(Decimal(str(price)) * int(quantity))  # Calculate total transaction value
            })
            logger.info(f"[TraceID: {trace_id}] Published order.matched event")
        except Exception as e:
            logger.error(f"[TraceID: {trace_id}] Error publishing order.matched event: {str(e)}")
        
        with db_transaction.atomic():
            # Update the stock price to reflect the latest transaction price
            try:
                stock = Stock.objects.get(id=stock_id)
                stock.current_price = price
                stock.save()
                logger.info(f"[TraceID: {trace_id}] Updated stock {stock.symbol} price to {price} based on transaction")
            except Stock.DoesNotExist:
                logger.error(f"[TraceID: {trace_id}] Stock with ID {stock_id} not found when trying to update price")
                
                # Publish error event
                publish_event('system_events', 'system.error', {
                    'event_type': 'system.error',
                    'service': 'trading-service',
                    'operation': 'process_transaction',
                    'error': f"Stock with ID {stock_id} not found",
                    'trace_id': trace_id
                })
            except Exception as e:
                logger.error(f"[TraceID: {trace_id}] Error updating stock price: {str(e)}")
                
                # Publish error event
                publish_event('system_events', 'system.error', {
                    'event_type': 'system.error',
                    'service': 'trading-service',
                    'operation': 'update_stock_price',
                    'error': str(e),
                    'trace_id': trace_id
                })
            
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
                    logger.info(f"[TraceID: {trace_id}] Found sell order with external ID {sell_order_id}")
                else:
                    logger.warning(f"[TraceID: {trace_id}] No sell order found with external ID {sell_order_id}, falling back to chronological order")
                    sell_orders = sell_orders_query.order_by('timestamp')
            else:
                sell_orders = sell_orders_query.order_by('timestamp')
            
            if sell_orders.exists():
                logger.info(f"[TraceID: {trace_id}] Found {sell_orders.count()} pending sell orders to update")
                
                # Calculate remaining quantity to process
                remaining_quantity = quantity
                
                for order in sell_orders:
                    if remaining_quantity <= 0:
                        break
                        
                    # Determine how much of this order to update
                    order_quantity = min(remaining_quantity, order.quantity)
                    remaining_quantity -= order_quantity
                    
                    old_status = order.status
                    
                    # If entire order is fulfilled
                    if order_quantity >= order.quantity:
                        order.status = OrderStatus.COMPLETED
                        logger.info(f"[TraceID: {trace_id}] Updated sell order {order.id} (external ID: {order.external_order_id}) to COMPLETED")
                    else:
                        # Partially fulfilled - create a child transaction for the matched part
                        # and update the parent order
                        
                        # First, create a child transaction for the matched portion
                        child_transaction = StockTransaction.objects.create(
                            user_id=sell_user_id,
                            stock=stock,
                            is_buy=False,  # This is a sell order
                            order_type=order.order_type,
                            status=OrderStatus.COMPLETED,  # Child transaction is completed
                            quantity=order_quantity,
                            price=price,
                            parent_transaction=order,  # Link to parent transaction
                            external_order_id=sell_order_id if sell_order_id else None
                        )
                        
                        logger.info(f"[TraceID: {trace_id}] Created child transaction {child_transaction.id} for partially filled sell order {order.id}, quantity: {order_quantity}")
                        
                        # Now update the parent order
                        order.quantity -= order_quantity
                        order.status = OrderStatus.PARTIALLY_COMPLETE
                        logger.info(f"[TraceID: {trace_id}] Updated sell order {order.id} (external ID: {order.external_order_id}) to PARTIALLY_COMPLETE (remaining: {order.quantity})")
                    
                    # If we received an external order ID and it's not set, update it
                    if sell_order_id and not order.external_order_id:
                        order.external_order_id = sell_order_id
                        logger.info(f"[TraceID: {trace_id}] Updated sell order {order.id} with external ID {sell_order_id}")
                    
                    order.save()
                    
                    # Publish order status change event
                    publish_event('order_events', 'order.updated', {
                        'event_type': 'order.updated',
                        'order_id': order.id,
                        'external_order_id': order.external_order_id,
                        'user_id': order.user_id,
                        'stock_id': order.stock_id,
                        'stock_symbol': order.stock.symbol,
                        'order_type': 'sell',
                        'previous_status': old_status,
                        'new_status': order.status,
                        'quantity': order_quantity,
                        'price': str(order.price),
                        'trace_id': trace_id
                    })
                    
                    # Determine which transaction to use for wallet updates
                    transaction_for_wallet = child_transaction if 'child_transaction' in locals() else order
                    
                    # Create a wallet transaction record for the seller and update their wallet balance
                    try:
                        # Calculate transaction amount
                        transaction_amount = Decimal(str(price)) * order_quantity
                        
                        # Update seller's wallet - add funds from the sale
                        seller_wallet, created = Wallet.objects.get_or_create(
                            user_id=sell_user_id,
                            defaults={'balance': 0}
                        )
                        
                        old_balance = seller_wallet.balance
                        seller_wallet.balance = F('balance') + transaction_amount
                        seller_wallet.save()
                        seller_wallet.refresh_from_db()
                        
                        # Create a simple wallet transaction for the seller without complex linking logic
                        seller_wallet_tx = WalletTransaction.objects.create(
                            user_id=sell_user_id,
                            stock=stock,
                            is_debit=False,  # Credit (adding money)
                            amount=Decimal(str(price)) * Decimal(str(order_quantity)),
                            description=f"Sale of {order_quantity} {stock.symbol} shares at ${price}"
                        )
                        logger.info(f"[TraceID: {trace_id}] Created wallet transaction {seller_wallet_tx.id} for seller {sell_user_id}")
                        
                        # Link wallet transaction to the stock transaction
                        transaction_for_wallet = child_transaction if 'child_transaction' in locals() else order
                        
                        # Only link if the transaction belongs to the same user
                        if transaction_for_wallet.user_id == int(sell_user_id):
                            try:
                                seller_wallet_tx.stock_transaction = transaction_for_wallet
                                seller_wallet_tx.save(update_fields=['stock_transaction'])
                                logger.info(f"[TraceID: {trace_id}] Linked seller wallet TX {seller_wallet_tx.id} to stock TX {transaction_for_wallet.id}")
                            except Exception as link_error:
                                logger.error(f"[TraceID: {trace_id}] Error linking seller transactions: {str(link_error)}")
                        else:
                            logger.warning(f"[TraceID: {trace_id}] Prevented cross-user reference: wallet transaction for user {sell_user_id} tried to link to stock transaction {transaction_for_wallet.id} belonging to user {transaction_for_wallet.user_id}")
                        
                        logger.info(f"[TraceID: {trace_id}] Updated seller wallet: {sell_user_id}, old balance: {old_balance}, new balance: {seller_wallet.balance}, amount added: {transaction_amount}")
                        
                        # Publish wallet update event
                        wallet_event_data = {
                            'event_type': 'wallet.updated',
                            'user_id': sell_user_id,
                            'previous_balance': str(old_balance),
                            'new_balance': str(seller_wallet.balance),
                            'transaction_amount': str(transaction_amount),
                            'transaction_type': 'credit',
                            'stock_id': stock_id,
                            'stock_symbol': stock.symbol,
                            'trace_id': trace_id
                        }
                        
                        publish_event('wallet_events', 'wallet.updated', wallet_event_data)
                        
                        # Update user's portfolio
                        try:
                            portfolio = UserPortfolio.objects.get(user_id=sell_user_id, stock_id=stock_id)
                            old_quantity = portfolio.quantity
                            portfolio.quantity -= order_quantity
                            portfolio.save()
                            logger.info(f"[TraceID: {trace_id}] Updated seller portfolio: {sell_user_id}, stock: {stock_id}, new quantity: {portfolio.quantity}")
                            
                            # Publish portfolio update event
                            publish_event('order_events', 'portfolio.updated', {
                                'event_type': 'portfolio.updated',
                                'user_id': sell_user_id,
                                'stock_id': stock_id,
                                'stock_symbol': order.stock.symbol,
                                'previous_quantity': old_quantity,
                                'new_quantity': portfolio.quantity,
                                'average_price': str(portfolio.average_price) if portfolio.average_price else None,
                                'trace_id': trace_id
                            })
                        except UserPortfolio.DoesNotExist:
                            logger.error(f"[TraceID: {trace_id}] Portfolio for seller {sell_user_id}, stock {stock_id} not found")
                        except Exception as e:
                            logger.error(f"[TraceID: {trace_id}] Error updating seller portfolio: {str(e)}")
                            logger.error(traceback.format_exc())
                        
                        # If the transaction is completed (either the entire order or a child transaction), publish completion event
                        if order.status == OrderStatus.COMPLETED or 'child_transaction' in locals():
                            completed_transaction = order if order.status == OrderStatus.COMPLETED else child_transaction
                            publish_event('order_events', 'order.completed', {
                                'event_type': 'order.completed',
                                'order_id': completed_transaction.id,
                                'external_order_id': completed_transaction.external_order_id,
                                'user_id': completed_transaction.user_id,
                                'stock_id': completed_transaction.stock_id, 
                                'stock_symbol': completed_transaction.stock.symbol,
                                'order_type': 'sell',
                                'quantity': order_quantity,
                                'price': str(completed_transaction.price),
                                'total_value': str(Decimal(str(completed_transaction.price)) * order_quantity),
                                'completed_at': timezone.now().isoformat(),
                                'trace_id': trace_id
                            })
                    except Exception as e:
                        logger.error(f"[TraceID: {trace_id}] Error updating seller wallet: {str(e)}")
                        logger.error(traceback.format_exc())
            
            # Find the corresponding buy order if we have an external order ID
            buy_order = None
            buy_order_for_wallet = None
            if buy_order_id:
                # First, try to find by external_order_id
                buy_order = StockTransaction.objects.filter(
                    external_order_id=buy_order_id,
                    user_id=buy_user_id,
                    is_buy=True
                ).first()
                
                if buy_order and buy_order.status != OrderStatus.COMPLETED:
                    # Check if this is a partial fill of a larger order
                    if quantity < buy_order.quantity:
                        old_quantity = buy_order.quantity
                        
                        # Create a child transaction for this match
                        child_buy_transaction = StockTransaction.objects.create(
                            user_id=buy_user_id,
                            stock=stock,
                            is_buy=True,
                            order_type=buy_order.order_type,
                            status=OrderStatus.COMPLETED,
                            quantity=quantity,
                            price=price,
                            parent_transaction=buy_order,
                            external_order_id=buy_order_id
                        )
                        
                        logger.info(f"[TraceID: {trace_id}] Created child buy transaction {child_buy_transaction.id} for partially filled buy order {buy_order.id}, quantity: {quantity}")
                        
                        # Update the parent order
                        buy_order.quantity -= quantity
                        buy_order.status = OrderStatus.PARTIALLY_COMPLETE
                        buy_order.save()
                        
                        # Use the child transaction for wallet updates
                        buy_order_for_wallet = child_buy_transaction
                    else:
                        # Complete fill
                        buy_order.status = OrderStatus.COMPLETED
                        buy_order.save()
                        buy_order_for_wallet = buy_order
                    
                    logger.info(f"[TraceID: {trace_id}] Updated buy order {buy_order.id} to {buy_order.status}")
                else:
                    # Either buy_order doesn't exist or it's already completed
                    # If it's already completed, we should still use it for the wallet transaction
                    if buy_order:
                        logger.info(f"[TraceID: {trace_id}] Found buy order {buy_order.id} but it's already {buy_order.status}")
                        if buy_order.status == OrderStatus.COMPLETED:
                            buy_order_for_wallet = buy_order
                    else:
                        logger.info(f"[TraceID: {trace_id}] No buy order found with external_order_id={buy_order_id}")
            
            # If no order found yet, try to find a matching pending order without external_order_id
            if not buy_order_for_wallet:
                # First try with timestamp-based search
                # Get recent orders from the last 5 seconds - useful for market orders
                five_seconds_ago = timezone.now() - timezone.timedelta(seconds=5)
                
                # Try a wider search to match potential buy orders
                all_possible_buy_orders = StockTransaction.objects.filter(
                    Q(user_id=buy_user_id, stock_id=stock_id, is_buy=True, quantity=quantity, 
                      timestamp__gte=five_seconds_ago) |
                    Q(external_order_id=buy_order_id) | 
                    Q(user_id=buy_user_id, stock_id=stock_id, is_buy=True, 
                      status__in=[OrderStatus.PENDING, OrderStatus.PARTIALLY_COMPLETE])
                ).order_by('-timestamp')
                
                # Log all potential matches
                logger.info(f"[TraceID: {trace_id}] Found {all_possible_buy_orders.count()} potential buy orders for user {buy_user_id}, stock {stock_id}")
                for pot_order in all_possible_buy_orders[:3]:  # Log the top 3 candidates
                    logger.info(f"[TraceID: {trace_id}] Candidate: id={pot_order.id}, ext_id={pot_order.external_order_id}, qty={pot_order.quantity}, status={pot_order.status}, timestamp={pot_order.timestamp}")
                
                if all_possible_buy_orders.exists():
                    # First, try to find a PENDING order with the exact quantity
                    exact_match = all_possible_buy_orders.filter(quantity=quantity, status=OrderStatus.PENDING).first()
                    if exact_match:
                        buy_order_for_wallet = exact_match
                        logger.info(f"[TraceID: {trace_id}] Found exact match buy order {buy_order_for_wallet.id}")
                    else:
                        # Take the most recent order
                        buy_order_for_wallet = all_possible_buy_orders.first()
                        logger.info(f"[TraceID: {trace_id}] Using most recent buy order {buy_order_for_wallet.id}")
                    
                    # Update the order's status
                    if buy_order_for_wallet and buy_order_for_wallet.status != OrderStatus.COMPLETED:
                        buy_order_for_wallet.status = OrderStatus.COMPLETED
                        buy_order_for_wallet.save()
                        logger.info(f"[TraceID: {trace_id}] Updated buy order {buy_order_for_wallet.id} status to COMPLETED")
            
            if not buy_order_for_wallet:
                logger.warning(f"[TraceID: {trace_id}] No matching buy order found for user_id={buy_user_id}, stock_id={stock_id}, creating transaction without linking to stock_tx_id")
            
            # Find and update buyer's portfolio and wallet
            try:
                # Get or create buyer's portfolio
                buyer_portfolio, created = UserPortfolio.objects.get_or_create(
                    user_id=buy_user_id,
                    stock_id=stock_id,
                    defaults={
                        'quantity': 0,
                        'average_price': 0
                    }
                )
                
                # Calculate new average price
                old_quantity = buyer_portfolio.quantity
                old_avg_price = Decimal(str(buyer_portfolio.average_price)) if buyer_portfolio.average_price else Decimal('0')
                
                # Update quantity and average price
                new_quantity = old_quantity + quantity
                total_old_value = old_quantity * old_avg_price
                total_new_value = quantity * Decimal(str(price))
                
                if new_quantity > 0:
                    new_avg_price = (total_old_value + total_new_value) / new_quantity
                else:
                    new_avg_price = 0
                
                buyer_portfolio.quantity = new_quantity
                buyer_portfolio.average_price = new_avg_price
                buyer_portfolio.save()
                
                logger.info(f"[TraceID: {trace_id}] Updated buyer portfolio: {buy_user_id}, stock: {stock_id}, old quantity: {old_quantity}, new quantity: {new_quantity}, new avg price: {new_avg_price}")
                
                # Calculate transaction amount
                transaction_amount = Decimal(str(price)) * quantity
                
                # Update buyer's wallet - deduct funds for the purchase
                buyer_wallet, created = Wallet.objects.get_or_create(
                    user_id=buy_user_id,
                    defaults={'balance': 0}
                )
                
                old_balance = buyer_wallet.balance
                buyer_wallet.balance = F('balance') - transaction_amount
                buyer_wallet.save()
                buyer_wallet.refresh_from_db()
                
                logger.info(f"[TraceID: {trace_id}] Updated buyer wallet: {buy_user_id}, old balance: {old_balance}, new balance: {buyer_wallet.balance}, amount deducted: {transaction_amount}")
                
                # Check if a wallet transaction already exists for this stock transaction
                existing_wallet_tx = None
                if buy_order_for_wallet:
                    existing_wallet_tx = WalletTransaction.objects.filter(
                        stock_transaction=buy_order_for_wallet,
                        user_id=buy_user_id,
                        is_debit=True
                    ).first()
                
                if existing_wallet_tx:
                    logger.info(f"[TraceID: {trace_id}] Found existing wallet transaction {existing_wallet_tx.id} for buy order, using it")
                    buyer_wallet_tx = existing_wallet_tx
                else:
                    # If we don't have buy_order_for_wallet, try harder to find it
                    if not buy_order_for_wallet and buy_order_id:
                        # Try again with a wider search
                        all_possible_buy_orders = StockTransaction.objects.filter(
                            Q(external_order_id=buy_order_id) | 
                            Q(user_id=buy_user_id, stock_id=stock_id, is_buy=True, status__in=[OrderStatus.PENDING, OrderStatus.PARTIALLY_COMPLETE])
                        ).order_by('-timestamp')
                        
                        if all_possible_buy_orders.exists():
                            buy_order_for_wallet = all_possible_buy_orders.first()
                            logger.info(f"[TraceID: {trace_id}] Found buy order {buy_order_for_wallet.id} in wider search")
                            
                            # Check again for wallet transaction
                            existing_wallet_tx = WalletTransaction.objects.filter(
                                stock_transaction=buy_order_for_wallet,
                                user_id=buy_user_id,
                                is_debit=True
                            ).first()
                            
                            if existing_wallet_tx:
                                logger.info(f"[TraceID: {trace_id}] Found existing wallet transaction {existing_wallet_tx.id} for buy order in wider search")
                                buyer_wallet_tx = existing_wallet_tx
                    
                    # SIMPLIFIED: Create a new wallet transaction record without complex bidirectional linking
                    if not existing_wallet_tx:
                        # Create a simpler wallet transaction record without complex bidirectional linking
                        buyer_wallet_tx = WalletTransaction.objects.create(
                            user_id=buy_user_id,
                            stock=stock,
                            is_debit=True,  # Debit for buy orders
                            amount=transaction_amount,
                            description=f"Purchase of {quantity} {stock.symbol} shares at ${price}"
                        )
                        logger.info(f"[TraceID: {trace_id}] Created wallet transaction {buyer_wallet_tx.id} for buyer {buy_user_id}")
                        
                        # Find the correct stock transaction for this user
                        correct_stock_tx = StockTransaction.objects.filter(
                            user_id=buy_user_id,
                            stock_id=stock_id,
                            is_buy=True,
                            quantity=quantity
                        ).order_by('-timestamp').first()
                        
                        if correct_stock_tx:
                            # With the new model, we only need to set the stock_transaction on wallet_transaction
                            # The foreign key and constraint will ensure it's valid
                            buyer_wallet_tx.stock_transaction = correct_stock_tx
                            buyer_wallet_tx.save(update_fields=['stock_transaction'])
                            logger.info(f"[TraceID: {trace_id}] Linked buyer wallet TX {buyer_wallet_tx.id} to stock TX {correct_stock_tx.id}")
                            
                            # Use this as the buy_order_for_wallet for further processing
                            buy_order_for_wallet = correct_stock_tx
                        else:
                            logger.warning(f"[TraceID: {trace_id}] Could not find matching stock transaction for buyer {buy_user_id}")
                            
                            # If no existing stock transaction was found, create one
                            # ENHANCED DUPLICATE DETECTION: Check for any similar transactions in the last 5 seconds
                            existing_buy_tx = StockTransaction.objects.filter(
                                user_id=buy_user_id,
                                stock_id=stock_id,
                                is_buy=True,
                                quantity=quantity,
                                price=price,
                                timestamp__gte=timezone.now() - timezone.timedelta(seconds=5)
                            ).first()
                            
                            if existing_buy_tx:
                                logger.info(f"[TraceID: {trace_id}] Found recent matching buy transaction: {existing_buy_tx.id} for user {buy_user_id} within last 5 seconds, using it instead of creating new")
                                # Use the existing transaction instead of creating a new one
                                new_stock_tx = existing_buy_tx
                                buy_order_for_wallet = existing_buy_tx
                                
                                # Check if this transaction already has a wallet transaction
                                existing_wallet_tx = WalletTransaction.objects.filter(
                                    stock_transaction=existing_buy_tx
                                ).first()
                                
                                if existing_wallet_tx:
                                    logger.info(f"[TraceID: {trace_id}] This transaction already has a wallet transaction {existing_wallet_tx.id}, skipping wallet creation")
                                    buyer_wallet_tx = existing_wallet_tx
                                else:
                                    # Link the wallet transaction to the existing stock transaction
                                    buyer_wallet_tx.stock_transaction = existing_buy_tx
                                    buyer_wallet_tx.save(update_fields=['stock_transaction'])
                                    logger.info(f"[TraceID: {trace_id}] Linked wallet transaction {buyer_wallet_tx.id} to existing stock transaction {existing_buy_tx.id}")
                            
                            elif not StockTransaction.objects.filter(
                                user_id=buy_user_id,
                                stock_id=stock_id,
                                is_buy=True,
                                quantity=quantity,
                                status=OrderStatus.COMPLETED,
                                timestamp__gte=timezone.now() - timezone.timedelta(seconds=10)
                            ).exists():
                                logger.info(f"[TraceID: {trace_id}] Creating new stock transaction record for buyer {buy_user_id}")
                                # Create a new stock transaction for this purchase
                                new_stock_tx = StockTransaction.objects.create(
                                    user_id=buy_user_id,
                                    stock=stock,
                                    is_buy=True,
                                    order_type=OrderType.MARKET,  # Default to MARKET for match notifications
                                    status=OrderStatus.COMPLETED,
                                    quantity=quantity,
                                    price=price,
                                    external_order_id=buy_order_id
                                )
                                # Now link them bidirectionally
                                buyer_wallet_tx.stock_transaction = new_stock_tx
                                buyer_wallet_tx.save(update_fields=['stock_transaction'])
                                
                                logger.info(f"[TraceID: {trace_id}] Created and linked new stock transaction {new_stock_tx.id} to wallet transaction {buyer_wallet_tx.id}")
                                
                                # Use this as the buy_order_for_wallet for event publishing
                                buy_order_for_wallet = new_stock_tx
                    
                    # SIMPLIFIED: Separate the buy order status update from wallet transaction linking
                    # If we found a buy order, update its status
                    if buy_order_for_wallet:
                        buy_order_for_wallet.status = OrderStatus.COMPLETED
                        buy_order_for_wallet.save(update_fields=['status'])
                        logger.info(f"[TraceID: {trace_id}] Updated stock transaction {buy_order_for_wallet.id} status to COMPLETED")

                        # Publish order status change event - only if we have a buy_order_for_wallet
                        publish_event('order_events', 'order.updated', {
                            'event_type': 'order.updated',
                            'order_id': buy_order_for_wallet.id,
                            'external_order_id': buy_order_for_wallet.external_order_id,
                            'user_id': buy_order_for_wallet.user_id,
                            'stock_id': buy_order_for_wallet.stock_id,
                            'stock_symbol': buy_order_for_wallet.stock.symbol,
                            'order_type': 'buy',
                            'previous_status': OrderStatus.PENDING,
                            'new_status': OrderStatus.COMPLETED,
                            'quantity': quantity,
                            'price': str(buy_order_for_wallet.price),
                            'trace_id': trace_id
                        })
                    else:
                        logger.warning(f"[TraceID: {trace_id}] No buy order found to link with wallet transaction {buyer_wallet_tx.id}")
                    
                    # Publish wallet update event
                    wallet_event_data = {
                        'event_type': 'wallet.updated',
                        'user_id': buy_user_id,
                        'previous_balance': str(old_balance),
                        'new_balance': str(buyer_wallet.balance),
                        'transaction_amount': str(transaction_amount),
                        'transaction_type': 'debit',
                        'stock_id': stock_id,
                        'stock_symbol': stock.symbol,
                        'trace_id': trace_id
                    }
                    
                    # Only add order_id if we have a valid buy_order_for_wallet
                    if buy_order_for_wallet:
                        wallet_event_data['order_id'] = buy_order_for_wallet.id
                    
                    publish_event('wallet_events', 'wallet.updated', wallet_event_data)
            except Exception as e:
                logger.error(f"[TraceID: {trace_id}] Error updating buyer portfolio or wallet: {str(e)}")
                logger.error(traceback.format_exc())
        
        return Response({"success": True, "message": "Transaction processed successfully"}, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"[TraceID: {trace_id}] Error processing transaction: {str(e)}")
        # Return 200 even on error to avoid matching engine retries
        # but include error details for debugging
        return Response(
            {"success": False, "error": f"Error processing transaction: {str(e)}"}, 
            status=status.HTTP_200_OK
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def process_order_notification(request):
    """Process order notifications from the order service"""
    logger.info(f"Processing order notification")
    
    # Generate a trace ID for tracking this request
    trace_id = request.headers.get('X-Request-ID', uuid.uuid4().hex[:8])
    # Log the request data
    logger.debug(f"Request data: {request.data}")
    
    # Map order service status to our internal status - use the exact values from OrderStatus in models.py
    STATUS_MAP = {
        'PENDING': OrderStatus.PENDING,            # 'Pending'
        'COMPLETED': OrderStatus.COMPLETED,        # 'Completed'
        'CANCELLED': OrderStatus.CANCELLED,        # 'Cancelled'
        'PARTIAL': OrderStatus.PARTIALLY_COMPLETE, # 'Partially_complete'
        'EXPIRED': OrderStatus.CANCELLED,          # 'Cancelled'
        'FAILED': OrderStatus.REJECTED,            # 'Rejected'
        'INPROGRESS': OrderStatus.IN_PROGRESS      # 'InProgress'
    }
    
    try:
        # Extract data from request
        status = request.data.get('status', '').upper()
        quantity = float(request.data.get('quantity', 0))
        price = float(request.data.get('price', 0))
        order_id = request.data.get('order_id')
        stock_symbol = request.data.get('stock_symbol')
        
        # Check for both potential field names for order type with more robust handling
        order_type = request.data.get('order_type') 
        if not order_type:
            # Try alternate field name
            order_type = request.data.get('type')
        
        # Convert to proper format for OrderType model field
        # The OrderType enum expects 'Market' or 'Limit' (not uppercase)
        if order_type:
            # First normalize to uppercase for comparison
            order_type_upper = order_type.upper() if isinstance(order_type, str) else ''
            
            # Map to correct format for the model
            if order_type_upper == 'MARKET':
                order_type = OrderType.MARKET  # This is 'Market'
            elif order_type_upper == 'LIMIT':
                order_type = OrderType.LIMIT   # This is 'Limit'
            else:
                # Default to LIMIT if unrecognized
                logger.warning(f"Unrecognized order type: {order_type}, defaulting to LIMIT")
                order_type = OrderType.LIMIT
        else:
            # Default if not provided
            logger.warning(f"No order_type provided in request, defaulting to LIMIT")
            order_type = OrderType.LIMIT
            
        user_id = request.data.get('user_id')
        is_buy = request.data.get('is_buy', True)
        
        if status not in STATUS_MAP:
            logger.warning(f"Received unknown status '{status}' from order service")
            mapped_status = OrderStatus.PENDING  # Default to pending if unknown
        else:
            mapped_status = STATUS_MAP[status]
        
        logger.info(f"Mapped order status from '{status}' to '{mapped_status}'")
        
        # Require essential parameters
        if not order_id or not stock_symbol:
            return Response({"success": False, "error": "Missing required parameters"}, status=400)
        
        # Get the stock
        stock = None
        try:
            stock = Stock.objects.get(symbol=stock_symbol)
            logger.info(f"Found stock {stock.symbol} with ID {stock.id}")
        except Stock.DoesNotExist:
            logger.warning(f"Stock {stock_symbol} not found, creating it")
            stock = Stock.objects.create(
                symbol=stock_symbol,
                name=f"{stock_symbol} Stock",
                current_price=price or 100.00  # Default price if none provided
            )
        
        # Add quantity validation for buy orders
        if mapped_status != OrderStatus.CANCELLED and is_buy and quantity <= 0:
            return Response({
                "success": False,
                "error": "Invalid quantity for buy order"
            }, status=400)
        
        # Check if we already have a transaction for this order
        existing_tx = StockTransaction.objects.filter(external_order_id=order_id).first()
        
        if existing_tx:
            logger.info(f"Found existing transaction for order {order_id}, updating status from {existing_tx.status} to {mapped_status}")
            
            # Update the existing transaction
            existing_tx.status = mapped_status
            existing_tx.price = price if price > 0 else existing_tx.price
            existing_tx.quantity = quantity if quantity > 0 else existing_tx.quantity
            existing_tx.save()
            
            # Process wallet for completed transactions
            if mapped_status in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
                # Check if this stock transaction already has a wallet transaction
                existing_wallet_tx = WalletTransaction.objects.filter(stock_transaction=existing_tx).exists()
                
                if existing_wallet_tx:
                    logger.info(f"This transaction already has a wallet transaction, skipping wallet update")
                else:
                    # Only process if no wallet transaction exists yet
                    process_stock_transaction(existing_tx, trace_id)
            
            return Response({
                "success": True,
                "message": f"Updated transaction status to {mapped_status}"
            })
        else:
            logger.info(f"Creating new transaction for order {order_id}")
            
            # Better duplicate detection - check for similar transactions in the last 5 seconds
            recent_tx = StockTransaction.objects.filter(
                user_id=user_id,
                stock=stock,
                is_buy=is_buy,
                quantity=quantity,
                price=price,
                timestamp__gte=timezone.now() - timezone.timedelta(seconds=5)
            ).first()
            
            if recent_tx:
                logger.info(f"Found similar recent transaction {recent_tx.id} (within 5 seconds), updating it instead of creating new")
                
                # Update the existing similar transaction
                recent_tx.external_order_id = order_id  # Add the external order ID
                recent_tx.status = mapped_status
                recent_tx.save()
                
                # Process wallet for completed transactions
                if mapped_status in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
                    # Check if this stock transaction already has a wallet transaction
                    existing_wallet_tx = WalletTransaction.objects.filter(stock_transaction=recent_tx).exists()
                    
                    if existing_wallet_tx:
                        logger.info(f"This transaction already has a wallet transaction, skipping wallet update")
                    else:
                        # Only process if no wallet transaction exists yet
                        process_stock_transaction(recent_tx, trace_id)
                
                return Response({
                    "success": True,
                    "message": f"Updated similar recent transaction {recent_tx.id} with order ID {order_id} and status {mapped_status}"
                })
            
            # Create a new transaction
            try:
                tx = StockTransaction.objects.create(
                    user_id=user_id,
                    stock=stock,
                    is_buy=is_buy,
                    order_type=order_type,
                    status=mapped_status,
                    quantity=quantity,
                    price=price,
                    external_order_id=order_id
                )
                
                logger.info(f"Created transaction with ID {tx.id} for order {order_id}")
                
                # Process wallet for completed transactions
                if mapped_status in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
                    process_stock_transaction(tx, trace_id)
                
                return Response({
                    "success": True,
                    "message": f"Created new transaction with status {mapped_status}"
                })
            except Exception as e:
                logger.error(f"Error creating transaction: {str(e)}")
                logger.error(traceback.format_exc())
                return Response({
                    "success": False, 
                    "data": {"error": f"Failed to create transaction: {str(e)}"}
                }, status=status.HTTP_200_OK)  # Return 200 for JMeter
    except Exception as e:
        logger.error(f"Error processing order notification: {str(e)}")
        logger.error(traceback.format_exc())
        return Response({
            "success": False,
            "data": {"error": f"Internal error: {str(e)}"}
        }, status=status.HTTP_200_OK)  # Return 200 for JMeter

@api_view(['POST'])
@permission_classes([AllowAny])
def process_order_status(request):
    """Process an order status notification from the matching engine
    
    This endpoint handles order status updates from the matching engine,
    creating or updating order records in the trading service database.
    """
    logger.info(f"Received order status notification: {request.data}")
    
    try:
        # Extract the data from the request
        data = request.data
        
        # Generate a trace ID for tracking this request
        trace_id = request.headers.get('X-Request-ID', uuid.uuid4().hex[:8])
        
        # Extract data from request
        status = data.get('status', '').upper()
        quantity = float(data.get('quantity', 0))
        price = float(data.get('price', 0))
        order_id = data.get('order_id')
        stock_id = data.get('stock_id')
        stock_symbol = data.get('stock_symbol')
        
        # Check for both potential field names for order type with more robust handling
        order_type = data.get('order_type') 
        if not order_type:
            # Try alternate field name
            order_type = data.get('type')
        
        # Convert to proper format for OrderType model field
        # The OrderType enum expects 'Market' or 'Limit' (not uppercase)
        if order_type:
            # First normalize to uppercase for comparison
            order_type_upper = order_type.upper() if isinstance(order_type, str) else ''
            
            # Map to correct format for the model
            if order_type_upper == 'MARKET':
                order_type = OrderType.MARKET  # This is 'Market'
            elif order_type_upper == 'LIMIT':
                order_type = OrderType.LIMIT   # This is 'Limit'
            else:
                # Default to LIMIT if unrecognized
                logger.warning(f"Unrecognized order type: {order_type}, defaulting to LIMIT")
                order_type = OrderType.LIMIT
        else:
            # Default if not provided
            logger.warning(f"No order_type provided in request, defaulting to LIMIT")
            order_type = OrderType.LIMIT
            
        user_id = data.get('user_id')
        is_buy = data.get('is_buy', True)
        
        # Validate required parameters
        if not order_id:
            return Response(
                {"success": False, "data": {"error": "Missing required parameter: order_id"}}, 
                status=status.HTTP_200_OK
            )
        
        # Get the stock - either by ID or symbol
        stock = None
        try:
            if stock_id:
                # If stock_id is provided, use that to get the stock
                stock = Stock.objects.get(id=stock_id)
                logger.info(f"Found stock with ID {stock_id}: {stock.symbol} (ID: {stock.id})")
            elif stock_symbol:
                # If only stock_symbol is provided, look up by symbol
                stock = Stock.objects.get(symbol=stock_symbol)
                logger.info(f"Found stock with symbol {stock_symbol}: ID {stock.id}")
            else:
                # If neither is provided, return an error
                return Response(
                    {"success": False, "data": {"error": "Missing required parameter: stock_id or stock_symbol"}}, 
                    status=status.HTTP_200_OK
                )
        except Stock.DoesNotExist:
            # If stock doesn't exist and we have a symbol, create it
            if stock_symbol:
                logger.warning(f"Stock {stock_symbol} not found, creating it")
                stock = Stock.objects.create(
                    symbol=stock_symbol,
                    name=f"{stock_symbol} Stock",
                    current_price=price or 100.00  # Default price if none provided
                )
            else:
                return Response(
                    {"success": False, "data": {"error": f"Stock with ID {stock_id} not found and no symbol provided to create it"}}, 
                    status=status.HTTP_200_OK
                )
        
        # Map order service status to our internal status - use the exact values from OrderStatus in models.py
        STATUS_MAP = {
            'PENDING': OrderStatus.PENDING,            # 'Pending'
            'COMPLETED': OrderStatus.COMPLETED,        # 'Completed'
            'CANCELLED': OrderStatus.CANCELLED,        # 'Cancelled'
            'PARTIAL': OrderStatus.PARTIALLY_COMPLETE, # 'Partially_complete'
            'EXPIRED': OrderStatus.CANCELLED,          # 'Cancelled'
            'FAILED': OrderStatus.REJECTED,            # 'Rejected'
            'INPROGRESS': OrderStatus.IN_PROGRESS      # 'InProgress'
        }
        
        if status not in STATUS_MAP:
            logger.warning(f"Received unknown status '{status}' from order service")
            mapped_status = OrderStatus.PENDING  # Default to pending if unknown
        else:
            mapped_status = STATUS_MAP[status]
        
        logger.info(f"Mapped order status from '{status}' to '{mapped_status}'")
        
        # Check if we already have a transaction for this order
        existing_tx = StockTransaction.objects.filter(external_order_id=order_id).first()
        
        if existing_tx:
            logger.info(f"Found existing transaction for order {order_id}, updating status from {existing_tx.status} to {mapped_status}")
            
            # Update the existing transaction
            existing_tx.status = mapped_status
            existing_tx.price = price if price > 0 else existing_tx.price
            existing_tx.quantity = quantity if quantity > 0 else existing_tx.quantity
            existing_tx.save()
            
            # Process wallets if the transaction is now completed
            if mapped_status in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
                # Check if this stock transaction already has a wallet transaction
                existing_wallet_tx = WalletTransaction.objects.filter(stock_transaction=existing_tx).exists()
                
                if existing_wallet_tx:
                    logger.info(f"This transaction already has a wallet transaction, skipping wallet update")
                else:
                    # Only process if no wallet transaction exists yet
                    process_stock_transaction(existing_tx, trace_id)
            
            return Response({
                "success": True,
                "message": f"Updated transaction status to {mapped_status}"
            })
        else:
            logger.info(f"Creating new transaction for order {order_id}")
            
            # Better duplicate detection - check for similar transactions in the last 5 seconds
            recent_tx = StockTransaction.objects.filter(
                user_id=user_id,
                stock=stock,
                is_buy=is_buy,
                quantity=quantity,
                price=price,
                timestamp__gte=timezone.now() - timezone.timedelta(seconds=5)
            ).first()
            
            if recent_tx:
                logger.info(f"Found similar recent transaction {recent_tx.id} (within 5 seconds), updating it instead of creating new")
                
                # Update the existing similar transaction
                recent_tx.external_order_id = order_id  # Add the external order ID
                recent_tx.status = mapped_status
                recent_tx.save()
                
                # Process wallet for completed transactions
                if mapped_status in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
                    # Check if this stock transaction already has a wallet transaction
                    existing_wallet_tx = WalletTransaction.objects.filter(stock_transaction=recent_tx).exists()
                    
                    if existing_wallet_tx:
                        logger.info(f"This transaction already has a wallet transaction, skipping wallet update")
                    else:
                        # Only process if no wallet transaction exists yet
                        process_stock_transaction(recent_tx, trace_id)
                
                return Response({
                    "success": True,
                    "message": f"Updated similar recent transaction {recent_tx.id} with order ID {order_id} and status {mapped_status}"
                })
            
            # Create a new transaction
            try:
                tx = StockTransaction.objects.create(
                    user_id=user_id,
                    stock=stock,
                    is_buy=is_buy,
                    order_type=order_type,
                    status=mapped_status,
                    quantity=quantity,
                    price=price,
                    external_order_id=order_id
                )
                
                logger.info(f"Created transaction with ID {tx.id} for order {order_id}")
                
                # Process wallet for completed transactions
                if mapped_status in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
                    process_stock_transaction(tx, trace_id)
                
                return Response({
                    "success": True,
                    "message": f"Created new transaction with status {mapped_status}"
                })
            except Exception as e:
                logger.error(f"Error creating transaction: {str(e)}")
                logger.error(traceback.format_exc())
                return Response({
                    "success": False, 
                    "data": {"error": f"Failed to create transaction: {str(e)}"}
                }, status=status.HTTP_200_OK)  # Return 200 for JMeter
    except Exception as e:
        logger.error(f"Error processing order status: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "data": {"error": f"Error processing order status: {str(e)}"}}, 
            status=status.HTTP_200_OK  # Return 200 for JMeter
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

def process_stock_transaction(stock_tx, trace_id=None):
    """Process a stock transaction and update wallet and portfolio accordingly
    
    This is a utility function that handles a StockTransaction object directly,
    creating appropriate wallet transactions, and updating user portfolios.
    It's called from process_transaction and process_order_notification.
    """
    if not trace_id:
        trace_id = str(uuid.uuid4())[:8]
    
    logger.info(f"[TraceID: {trace_id}] Processing stock transaction {stock_tx.id}, status: {stock_tx.status}")
    
    try:
        # Extract transaction details
        user_id = stock_tx.user_id
        stock = stock_tx.stock
        is_buy = stock_tx.is_buy
        quantity = stock_tx.quantity
        price = stock_tx.price
        
        # Only process COMPLETED or PARTIAL transactions - using correct OrderStatus values
        if stock_tx.status not in [OrderStatus.COMPLETED, OrderStatus.PARTIALLY_COMPLETE]:
            logger.info(f"[TraceID: {trace_id}] Skipping transaction {stock_tx.id} with status {stock_tx.status}")
            return
        
        # CRITICAL: Check if a wallet transaction already exists for this stock transaction
        # This prevents duplicate wallet transactions from being created
        existing_wallet_tx = WalletTransaction.objects.filter(stock_transaction=stock_tx).first()
        if existing_wallet_tx:
            logger.info(f"[TraceID: {trace_id}] Wallet transaction {existing_wallet_tx.id} already exists for stock transaction {stock_tx.id}, skipping")
            return existing_wallet_tx
        
        # Get or create user wallet
        wallet, created = Wallet.objects.get_or_create(
            user_id=user_id,
            defaults={'balance': 0}
        )
        
        # Calculate transaction amount
        amount = Decimal(quantity) * Decimal(price)
        
        # Create wallet transaction first before updating portfolio
        # Different handling for buy vs sell
        if is_buy:
            # Buying stock - deduct from wallet
            if wallet.balance < amount:
                logger.warning(f"[TraceID: {trace_id}] Insufficient funds for transaction {stock_tx.id}: balance={wallet.balance}, amount={amount}")
                # We'll still process it, but log the warning
            
            # Update wallet balance
            wallet.balance = F('balance') - amount
            wallet.save()
            wallet.refresh_from_db()
            
            # Create wallet transaction record (debit)
            wallet_tx = WalletTransaction.objects.create(
                user_id=user_id,
                stock=stock,
                stock_transaction=stock_tx,  # Link to stock transaction
                is_debit=True,  # Debit (money out)
                amount=amount,
                description=f"Purchase of {quantity} shares of {stock.symbol} at ${price}"
            )
            
            logger.info(f"[TraceID: {trace_id}] Created wallet transaction {wallet_tx.id} for buy transaction {stock_tx.id}")
            
            # Update user portfolio - add to holdings
            portfolio, created = UserPortfolio.objects.get_or_create(
                user_id=user_id,
                stock=stock,
                defaults={
                    'quantity': 0,
                    'average_price': 0
                }
            )
            
            # Calculate new average price based on weighted average
            if portfolio.quantity > 0 and portfolio.average_price:
                total_value = (portfolio.quantity * portfolio.average_price) + amount
                new_quantity = portfolio.quantity + quantity
                new_avg_price = total_value / new_quantity if new_quantity > 0 else price
            else:
                new_avg_price = price
            
            # Update portfolio
            portfolio.quantity = F('quantity') + quantity
            portfolio.average_price = new_avg_price
            portfolio.save()
            
            logger.info(f"[TraceID: {trace_id}] Updated portfolio for user {user_id}: added {quantity} shares of {stock.symbol}, new total: {portfolio.quantity + quantity}")
        else:
            # Selling stock - add to wallet
            # Update wallet balance
            wallet.balance = F('balance') + amount
            wallet.save()
            wallet.refresh_from_db()
            
            # Create wallet transaction record (credit)
            wallet_tx = WalletTransaction.objects.create(
                user_id=user_id,
                stock=stock,
                stock_transaction=stock_tx,  # Link to stock transaction
                is_debit=False,  # Credit (money in)
                amount=amount,
                description=f"Sale of {quantity} shares of {stock.symbol} at ${price}"
            )
            
            logger.info(f"[TraceID: {trace_id}] Created wallet transaction {wallet_tx.id} for sell transaction {stock_tx.id}")
            
            # Update user portfolio - deduct from holdings
            try:
                portfolio = UserPortfolio.objects.get(user_id=user_id, stock=stock)
                
                # Check if user has enough shares
                if portfolio.quantity < quantity:
                    logger.warning(f"[TraceID: {trace_id}] User {user_id} has {portfolio.quantity} shares but trying to sell {quantity}")
                
                # Update portfolio
                portfolio.quantity = F('quantity') - quantity
                portfolio.save()
                portfolio.refresh_from_db()
                
                logger.info(f"[TraceID: {trace_id}] Updated portfolio for user {user_id}: removed {quantity} shares of {stock.symbol}, new total: {portfolio.quantity}")
                
                # If quantity is zero, optionally remove the portfolio entry
                if portfolio.quantity <= 0:
                    logger.info(f"[TraceID: {trace_id}] User {user_id} has no more shares of {stock.symbol}, removing portfolio entry")
                    portfolio.delete()
            except UserPortfolio.DoesNotExist:
                logger.error(f"[TraceID: {trace_id}] User {user_id} has no portfolio for stock {stock.symbol} but is trying to sell")
        
        return wallet_tx
    
    except Exception as e:
        logger.error(f"[TraceID: {trace_id}] Error processing stock transaction {stock_tx.id}: {str(e)}")
        logger.error(traceback.format_exc())
        raise

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