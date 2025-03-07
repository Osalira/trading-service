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
import traceback

from trading_app.models import Stock, UserPortfolio, Wallet, StockTransaction, WalletTransaction, OrderStatus
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
    """Get the user's stock portfolio (open to any authenticated user)"""
    # Check for specific user_id in query parameters
    query_user_id = request.query_params.get('user_id')
    if query_user_id:
        logger.info(f"Using user_id {query_user_id} from query parameters")
        user_id = query_user_id
    
        # Fall back to standard user_id extraction
        user_id = get_user_id(request)
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
        
        # Fetch the transactions ordered by timestamp (newest first) to match wallet transactions view
        transactions = StockTransaction.objects.filter(user_id=user_id).order_by('timestamp')
        
        # Use select_related to fetch related objects in one query
        transactions = transactions.select_related('stock', 'wallet_transaction', 'parent_transaction')
        
        logger.debug(f"Found {transactions.count()} transactions")
        
        # Check for transactions with inconsistent wallet links (advanced diagnostics)
        for tx in transactions:
            if tx.wallet_transaction_id is not None:
                # Verify wallet transaction exists and points back
                try:
                    wallet_tx = WalletTransaction.objects.get(id=tx.wallet_transaction_id)
                    if wallet_tx.stock_transaction_id != tx.id:
                        logger.warning(f"LINK INCONSISTENCY: Stock transaction {tx.id} points to wallet transaction {tx.wallet_transaction_id}, but wallet transaction points to stock transaction {wallet_tx.stock_transaction_id}")
                except WalletTransaction.DoesNotExist:
                    logger.warning(f"LINK INCONSISTENCY: Stock transaction {tx.id} points to non-existent wallet transaction {tx.wallet_transaction_id}")
            
            # Check if there's a wallet transaction pointing to this stock transaction
            wallet_txs = WalletTransaction.objects.filter(stock_transaction_id=tx.id)
            if wallet_txs.exists():
                if tx.wallet_transaction_id is None:
                    logger.warning(f"LINK INCONSISTENCY: Stock transaction {tx.id} has null wallet_transaction_id, but wallet transaction {wallet_txs.first().id} points to it")
                elif tx.wallet_transaction_id != wallet_txs.first().id:
                    logger.warning(f"LINK INCONSISTENCY: Stock transaction {tx.id} points to wallet transaction {tx.wallet_transaction_id}, but wallet transaction {wallet_txs.first().id} points to it")
        
        # Fix wallet transaction links for transactions with missing links
        for tx in transactions:
            if tx.wallet_transaction is None:
                fixed = fix_missing_wallet_link(tx)
                if fixed:
                    logger.info(f"Fixed missing wallet link for stock transaction {tx.id}")
        
        # Apply pagination if needed
        if limit > 0:
            transactions = transactions[offset:offset+limit]
        
        # Log details of each transaction for debugging
        for tx in transactions:
            logger.debug(f"Transaction {tx.id}: stock={tx.stock_id}, price={tx.price}, wallet_tx={tx.wallet_transaction.id if tx.wallet_transaction else None}")
            
            # Try to fix null wallet_tx_id field for JMeter serializer
            if tx.wallet_transaction is None:
                wallet_tx = WalletTransaction.objects.filter(stock_transaction=tx).first()
                if wallet_tx:
                    logger.info(f"Found wallet transaction {wallet_tx.id} for stock transaction {tx.id} via reverse lookup")
            
            if tx.order_type == 'MARKET' and tx.price == 0 and tx.wallet_transaction:
                # For market orders with zero price but valid wallet transaction,
                # log the actual price from the wallet transaction
                if tx.quantity > 0:
                    logger.debug(f"  Market order with wallet_tx amount={tx.wallet_transaction.amount}, calculated price={tx.wallet_transaction.amount/tx.quantity}")
        
        # Serialize the data using JMeter format
        serialized_data = JMeterStockTransactionSerializer(transactions, many=True).data
        
        # Return with success key for consistency with other endpoints
        return Response({"success": True, "data": serialized_data})
    
    except Exception as e:
        logger.error(f"Error fetching stock transactions: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return Response({"success": False, "error": "Internal server error"}, status=500)

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
            {"success": False, "error": "User ID not provided"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Get transaction parameters from query string
        limit = int(request.query_params.get('limit', 50))
        offset = int(request.query_params.get('offset', 0))
        
        # Get all user's transactions but handle duplicates
        all_transactions = WalletTransaction.objects.filter(user_id=user_id)
        
        # Diagnostic: Check for inconsistent links with stock transactions
        for tx in all_transactions:
            if tx.stock_transaction_id is not None:
                # Check if the referenced stock transaction exists
                try:
                    stock_tx = StockTransaction.objects.get(id=tx.stock_transaction_id)
                    
                    # Check if stock transaction belongs to the same user
                    if stock_tx.user_id != int(user_id):
                        logger.warning(f"CROSS-USER REFERENCE: Wallet transaction {tx.id} for user {user_id} references stock transaction {tx.stock_transaction_id} belonging to user {stock_tx.user_id}")
                    
                    # Check if stock transaction points back to this wallet transaction
                    if stock_tx.wallet_transaction_id != tx.id:
                        logger.warning(f"LINK INCONSISTENCY: Wallet transaction {tx.id} references stock transaction {tx.stock_transaction_id}, but stock transaction points to wallet transaction {stock_tx.wallet_transaction_id if stock_tx.wallet_transaction else None}")
                        
                        # Try to find a better matching stock transaction for this user
                        matching_stock_tx = StockTransaction.objects.filter(
                            user_id=user_id,
                            stock_id=tx.stock_id,
                            wallet_transaction__isnull=True
                        ).order_by('timestamp').first()
                        
                        if matching_stock_tx:
                            logger.info(f"Found potential match: Stock transaction {matching_stock_tx.id} for the same user {user_id}")
                        
                except StockTransaction.DoesNotExist:
                    logger.warning(f"INVALID REFERENCE: Wallet transaction {tx.id} references non-existent stock transaction {tx.stock_transaction_id}")
        
        # Process transactions to handle potential duplicates where stock_transaction is null
        # First, collect all transactions with non-null stock_transaction
        transactions_with_stock_tx = list(all_transactions.exclude(stock_transaction__isnull=True))
        
        # Now collect all transactions with null stock_transaction
        transactions_with_null_stock_tx = list(all_transactions.filter(stock_transaction__isnull=True))
        
        # Create a dictionary to track duplicates by key attributes + timestamp window
        # We'll use a window of 2 seconds to consider transactions as potential duplicates
        tx_groups = {}
        
        # First, group the transactions with non-null stock_tx_id
        for tx in transactions_with_stock_tx:
            # Create a more unique key based on user, type, amount, stock, and stock_transaction
            if tx.stock_transaction:
                base_key = f"{tx.user_id}_{tx.is_debit}_{tx.amount}_{tx.stock_id if tx.stock_id else 'None'}_{tx.stock_transaction.id}"
            else:
                base_key = f"{tx.user_id}_{tx.is_debit}_{tx.amount}_{tx.stock_id if tx.stock_id else 'None'}_no_stock_tx"
            
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
        
        logger.info(f"Fetched {len(transactions)} wallet transactions for user {user_id} after filtering {len(duplicate_ids)} duplicates")
        
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
            {"success": False, "error": str(e)}, 
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
                            external_order_id=sell_order_id if sell_order_id else None,
                            wallet_transaction=None  # Explicitly set to None - will be linked properly in process_transaction
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
                        
                        # Check if a wallet transaction already exists for this stock transaction
                        existing_wallet_tx = WalletTransaction.objects.filter(
                            stock_transaction=transaction_for_wallet,
                            user_id=sell_user_id,
                            is_debit=False
                        ).first()
                        
                        if existing_wallet_tx:
                            logger.info(f"[TraceID: {trace_id}] Found existing wallet transaction {existing_wallet_tx.id} for sell order, using it")
                            seller_wallet_tx = existing_wallet_tx
                        else:
                            # If we don't have a valid transaction_for_wallet, try harder to find it
                            if not transaction_for_wallet and sell_order_id:
                                # Try again with a wider search
                                all_possible_sell_orders = StockTransaction.objects.filter(
                                    Q(external_order_id=sell_order_id) | 
                                    Q(user_id=sell_user_id, stock_id=stock_id, is_buy=False, status__in=[OrderStatus.PENDING, OrderStatus.PARTIALLY_COMPLETE])
                                ).order_by('-timestamp')
                                
                                if all_possible_sell_orders.exists():
                                    transaction_for_wallet = all_possible_sell_orders.first()
                                    logger.info(f"[TraceID: {trace_id}] Found sell order {transaction_for_wallet.id} in wider search")
                                    
                                    # Check again for wallet transaction
                                    existing_wallet_tx = WalletTransaction.objects.filter(
                                        stock_transaction=transaction_for_wallet,
                                        user_id=sell_user_id,
                                        is_debit=False
                                    ).first()
                                    
                                    if existing_wallet_tx:
                                        logger.info(f"[TraceID: {trace_id}] Found existing wallet transaction {existing_wallet_tx.id} for sell order in wider search")
                                        seller_wallet_tx = existing_wallet_tx
                            
                            # Create wallet transaction if we didn't find an existing one
                            if not existing_wallet_tx:
                                # Create wallet transaction record first without the stock_transaction relation
                                seller_wallet_tx = WalletTransaction.objects.create(
                                    user_id=sell_user_id,
                                    stock=stock,
                                    is_debit=False,  # Credit (adding money)
                                    amount=Decimal(str(price)) * Decimal(str(quantity)),
                                    description=f"Sale of {quantity} {stock.symbol} shares at ${price}",
                                    stock_transaction=None  # Explicitly set to null initially to avoid circular linking issues
                                )
                                logger.info(f"[TraceID: {trace_id}] Created wallet transaction {seller_wallet_tx.id} for seller")
                                
                                # Use the utility function to ensure consistent bidirectional links
                                transaction_for_wallet, seller_wallet_tx = ensure_consistent_transaction_links(transaction_for_wallet, seller_wallet_tx)
                                logger.info(f"[TraceID: {trace_id}] Established bidirectional link between stock TX {transaction_for_wallet.id} and wallet TX {seller_wallet_tx.id}")
                        
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
                        
                        # Only add order_id if we have a valid sell_order_for_wallet
                        if transaction_for_wallet:
                            wallet_event_data['order_id'] = transaction_for_wallet.id
                        
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
                            external_order_id=buy_order_id,
                            wallet_transaction=None  # Explicitly set to None - will be linked properly in process_transaction
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
                    
                    # Create wallet transaction if we didn't find an existing one
                    if not existing_wallet_tx:
                        # Create wallet transaction record
                        buyer_wallet_tx = WalletTransaction.objects.create(
                            user_id=buy_user_id,
                            stock=stock,
                            is_debit=True,  # Debit for buy orders
                            amount=transaction_amount,
                            description=f"Purchase of {quantity} {stock.symbol} shares at ${price}",
                            stock_transaction=None  # Explicitly set to null initially to avoid circular linking issues
                        )
                        logger.info(f"[TraceID: {trace_id}] Created wallet transaction {buyer_wallet_tx.id} for buyer")
                
                # If we found a buy order, link the wallet transaction to it
                if buy_order_for_wallet:
                    # Use the utility function to ensure consistent bidirectional links
                    buy_order_for_wallet, buyer_wallet_tx = ensure_consistent_transaction_links(buy_order_for_wallet, buyer_wallet_tx)
                    
                    # Update the order status
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

def process_order_notification(data, trace_id=None):
    """Process a new order notification from the matching engine"""
    if not trace_id:
        trace_id = uuid.uuid4().hex[:8]
        
    logger.info(f"[TraceID: {trace_id}] Processing order notification: {data}")
    
    user_id = data.get('user_id')
    stock_id = data.get('stock_id')
    order_type = data.get('order_type')  # This is 'Market' or 'Limit', not buy/sell
    price = data.get('price')
    quantity = data.get('quantity')
    external_order_id = data.get('order_id')  # ID from matching engine
    
    # Get the buy/sell flag directly from the notification
    is_buy = data.get('is_buy')
    
    # Get the limit type (Market or Limit) from the notification
    # The matching engine sends this as order_type, not to be confused with buy/sell
    limit_type = data.get('order_type', 'Limit')  # Get the order type (Market or Limit)
    
    # Get the status from the notification, default to PENDING if not provided
    order_status = data.get('status', OrderStatus.PENDING)
    
    # Check if the order is completed or partially completed
    if order_status in ["Completed", "Partially_complete"]:
        # Map to the corresponding enum values
        if order_status == "Completed":
            order_status = OrderStatus.COMPLETED
        else:
            order_status = OrderStatus.PARTIALLY_COMPLETE
    elif order_status == "Cancelled":
        order_status = OrderStatus.CANCELLED
    
    logger.debug(f"[TraceID: {trace_id}] Parsed order details - is_buy: {is_buy}, limit_type: {limit_type}, status: {order_status}")
    
    if not all([user_id, stock_id, price, quantity, external_order_id]):
        logger.error(f"[TraceID: {trace_id}] Missing required fields in order notification: {data}")
        
        # Publish error event
        try:
            publish_event('system_events', 'system.error', {
                'event_type': 'system.error',
                'service': 'trading-service',
                'operation': 'process_order_notification',
                'error': 'Missing required fields in order notification',
                'trace_id': trace_id,
                'data': data
            })
        except Exception as e:
            logger.error(f"[TraceID: {trace_id}] Error publishing error event: {str(e)}")
        
        return Response(
            {"success": False, "error": "Missing required fields in order notification"}, 
            status=status.HTTP_200_OK  # Return 200 to avoid retries
        )
    
    # Check if order already exists
    existing_order = StockTransaction.objects.filter(
        external_order_id=external_order_id
    ).first()
    
    if existing_order:
        logger.info(f"[TraceID: {trace_id}] Order with external ID {external_order_id} already exists, updating status")
        
        # Update the status if it's different
        if existing_order.status != order_status:
            old_status = existing_order.status
            existing_order.status = order_status
            existing_order.save()
            
            logger.info(f"[TraceID: {trace_id}] Updated order {existing_order.id} status from {old_status} to {order_status}")
            
            # Publish order status change event
            try:
                publish_event('order_events', 'order.updated', {
                    'event_type': 'order.updated',
                    'order_id': existing_order.id,
                    'external_order_id': external_order_id,
                    'user_id': existing_order.user_id,
                    'stock_id': existing_order.stock_id,
                    'stock_symbol': existing_order.stock.symbol if hasattr(existing_order, 'stock') and existing_order.stock else "Unknown",
                    'order_type': 'buy' if existing_order.is_buy else 'sell',
                    'previous_status': old_status,
                    'new_status': order_status,
                    'quantity': existing_order.quantity,
                    'price': str(existing_order.price),
                    'trace_id': trace_id
                })
            except Exception as e:
                logger.error(f"[TraceID: {trace_id}] Error publishing order.updated event: {str(e)}")
        
        return Response({"success": True, "message": f"Order status updated to {order_status}"}, status=status.HTTP_200_OK)
    
    # Also check for recent transactions using the same user/stock/is_buy
    from datetime import timedelta
    
    time_window = 5  # seconds
    time_lower = timezone.now() - timedelta(seconds=time_window)
    
    similar_tx = StockTransaction.objects.filter(
        user_id=user_id,
        stock_id=stock_id,
        is_buy=is_buy,
        quantity=quantity,
        price=price,
        timestamp__gte=time_lower
    ).first()
    
    if similar_tx:
        logger.info(f"[TraceID: {trace_id}] Found a similar recent transaction (ID: {similar_tx.id}), updating it instead of creating new")
        
        # Update external_order_id if it was missing
        if not similar_tx.external_order_id:
            similar_tx.external_order_id = external_order_id
        
        # Update status if needed
        if similar_tx.status != order_status:
            old_status = similar_tx.status
            similar_tx.status = order_status
            similar_tx.save()
            
            logger.info(f"[TraceID: {trace_id}] Updated similar transaction {similar_tx.id} status from {old_status} to {order_status}")
            
        return Response({"success": True, "message": f"Updated similar recent transaction"}, status=status.HTTP_200_OK)
        
    # At this point we know we need to create a new transaction
    try:
        stock = Stock.objects.get(id=stock_id)
    except Stock.DoesNotExist:
        logger.error(f"[TraceID: {trace_id}] Stock with ID {stock_id} not found")
        
        # Publish error event
        try:
            publish_event('system_events', 'system.error', {
                'event_type': 'system.error',
                'service': 'trading-service',
                'operation': 'process_order_notification',
                'error': f"Stock with ID {stock_id} not found",
                'trace_id': trace_id
            })
        except Exception as e:
            logger.error(f"[TraceID: {trace_id}] Error publishing error event: {str(e)}")
        
        return Response(
            {"success": False, "error": f"Stock with ID {stock_id} not found"}, 
            status=status.HTTP_200_OK
        )
    
    # Create the stock transaction
    new_order = StockTransaction.objects.create(
        user_id=user_id,
        stock=stock,
        is_buy=is_buy,
        order_type=limit_type,
        status=order_status,
        quantity=quantity,
        price=price,
        external_order_id=external_order_id,
        wallet_transaction=None  # Always ensure wallet_transaction is None when created
    )
    
    logger.info(f"[TraceID: {trace_id}] Created new {limit_type.lower()} {'buy' if is_buy else 'sell'} order with ID {new_order.id}, external ID {external_order_id}, type {limit_type}, status {order_status}")
    
    # Publish order created event
    try:
        publish_event('order_events', 'order.created', {
            'event_type': 'order.created',
            'order_id': new_order.id,
            'external_order_id': external_order_id,
            'user_id': user_id,
            'stock_id': stock_id,
            'stock_symbol': stock.symbol,
            'order_type': 'buy' if is_buy else 'sell',
            'status': order_status,
            'quantity': quantity,
            'price': str(price),
            'trace_id': trace_id
        })
    except Exception as e:
        logger.error(f"[TraceID: {trace_id}] Error publishing order.created event: {str(e)}")
    
    # Return early if this is a MARKET order with COMPLETED status 
    # (portfolio/wallet updates will be handled by process_transaction)
    if limit_type == "Market" and order_status == OrderStatus.COMPLETED:
        logger.info(f"[TraceID: {trace_id}] MARKET order with COMPLETED status detected. Portfolio and wallet updates will be handled by process_transaction.")
        logger.info(f"[TraceID: {trace_id}] NOT updating portfolio or creating wallet transaction in process_order_notification.")
        return Response({"success": True, "message": "Order created", "order_id": new_order.id}, status=status.HTTP_200_OK)
    
    # For other order types and statuses, continue with regular processing
    # Return response
    return Response(
        {"success": True, "message": "Order created", "order_id": new_order.id}, 
        status=status.HTTP_200_OK
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
        # Generate a trace ID for tracking this request
        trace_id = request.headers.get('X-Request-ID', uuid.uuid4().hex[:8])
        
        # Process the notification
        result = process_order_notification(request.data, trace_id)
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

@api_view(['POST'])
@permission_classes([AllowAny])
def fix_transaction_links(request):
    """Maintenance endpoint to fix links between stock and wallet transactions"""
    try:
        # Get scope of fix - default to 'all'
        scope = request.data.get('scope', 'all')
        
        # Track counts for reporting
        fixed_count = 0
        examined_count = 0
        
        # Find stock transactions with null wallet_transaction but having a wallet transaction with stock_transaction reference
        stock_txs_to_fix = StockTransaction.objects.filter(
            wallet_transaction__isnull=True
        )
        
        logger.info(f"Found {stock_txs_to_fix.count()} stock transactions with missing wallet_transaction links")
        
        for stock_tx in stock_txs_to_fix:
            examined_count += 1
            
            # STEP 1: Look for wallet transaction with this stock_transaction reference
            wallet_tx = WalletTransaction.objects.filter(stock_transaction=stock_tx).first()
            
            if wallet_tx:
                # Create a bidirectional link - ensure both FK and FK ID are set
                stock_tx.wallet_transaction = wallet_tx
                stock_tx.save(update_fields=['wallet_transaction'])
                
                # Make sure stock_transaction_id is also set in wallet_tx
                if not wallet_tx.stock_transaction_id or wallet_tx.stock_transaction_id != stock_tx.id:
                    wallet_tx.stock_transaction_id = stock_tx.id
                    wallet_tx.save(update_fields=['stock_transaction_id'])
                    
                fixed_count += 1
                logger.info(f"Fixed link between stock tx {stock_tx.id} and wallet tx {wallet_tx.id}")
                continue
        
        # STEP 2: Also find wallet transactions with null stock_transaction_id but linked from a stock transaction
        wallet_txs_to_fix = WalletTransaction.objects.filter(
            stock_transaction_id__isnull=True
        )
        
        logger.info(f"Found {wallet_txs_to_fix.count()} wallet transactions with missing stock_transaction_id")
        
        for wallet_tx in wallet_txs_to_fix:
            examined_count += 1
            
            # Look for stock transaction that links to this wallet transaction
            stock_tx = StockTransaction.objects.filter(wallet_transaction=wallet_tx).first()
            
            if stock_tx:
                # Update the stock_transaction_id
                wallet_tx.stock_transaction = stock_tx
                wallet_tx.stock_transaction_id = stock_tx.id
                wallet_tx.save(update_fields=['stock_transaction', 'stock_transaction_id'])
                fixed_count += 1
                logger.info(f"Fixed stock_transaction_id for wallet tx {wallet_tx.id} to {stock_tx.id}")
        
        # STEP 3: Find mismatched links (stock_tx.wallet_transaction points to wallet_tx1,
        # but wallet_tx1.stock_transaction points to a different stock_tx2)
        all_stock_txs_with_wallet = StockTransaction.objects.filter(
            wallet_transaction__isnull=False
        ).select_related('wallet_transaction')
        
        for stock_tx in all_stock_txs_with_wallet:
            examined_count += 1
            wallet_tx = stock_tx.wallet_transaction
            
            # If the wallet transaction's stock_transaction doesn't point back to this stock_tx,
            # we have a mismatch that needs to be fixed
            if wallet_tx.stock_transaction_id != stock_tx.id:
                logger.info(f"Found mismatched bidirectional link: Stock TX {stock_tx.id} points to Wallet TX {wallet_tx.id}, but Wallet TX points to Stock TX {wallet_tx.stock_transaction_id}")
                
                # Fix the link
                wallet_tx.stock_transaction = stock_tx
                wallet_tx.stock_transaction_id = stock_tx.id
                wallet_tx.save(update_fields=['stock_transaction', 'stock_transaction_id'])
                fixed_count += 1
                logger.info(f"Fixed mismatched link: Wallet TX {wallet_tx.id} now properly points to Stock TX {stock_tx.id}")
        
        # STEP 4: Check the reverse direction as well
        all_wallet_txs_with_stock = WalletTransaction.objects.filter(
            stock_transaction__isnull=False
        ).select_related('stock_transaction')
        
        for wallet_tx in all_wallet_txs_with_stock:
            examined_count += 1
            stock_tx = wallet_tx.stock_transaction
            
            # If the stock transaction's wallet_transaction doesn't point back to this wallet_tx,
            # we have a mismatch that needs to be fixed
            if stock_tx.wallet_transaction_id != wallet_tx.id:
                logger.info(f"Found mismatched bidirectional link: Wallet TX {wallet_tx.id} points to Stock TX {stock_tx.id}, but Stock TX points to Wallet TX {stock_tx.wallet_transaction_id}")
                
                # Fix the link
                stock_tx.wallet_transaction = wallet_tx
                stock_tx.save(update_fields=['wallet_transaction'])
                fixed_count += 1
                logger.info(f"Fixed mismatched link: Stock TX {stock_tx.id} now properly points to Wallet TX {wallet_tx.id}")
        
        # NEW STEP 5: Fix cross-user references (wallet transactions linked to another user's stock transactions)
        all_wallet_txs = WalletTransaction.objects.filter(
            stock_transaction_id__isnull=False
        ).select_related('stock_transaction')
        
        logger.info(f"Checking {all_wallet_txs.count()} wallet transactions for cross-user references")
        
        for wallet_tx in all_wallet_txs:
            examined_count += 1
            stock_tx = wallet_tx.stock_transaction
            
            # If the wallet transaction and stock transaction belong to different users,
            # we likely have a cross-user reference issue
            if wallet_tx.user_id != stock_tx.user_id:
                logger.info(f"Found cross-user reference: Wallet TX {wallet_tx.id} (user {wallet_tx.user_id}) references Stock TX {stock_tx.id} (user {stock_tx.user_id})")
                
                # Look for a stock transaction belonging to the wallet's user that should be linked instead
                correct_stock_tx = StockTransaction.objects.filter(
                    user_id=wallet_tx.user_id,
                    stock_id=stock_tx.stock_id,
                    wallet_transaction__isnull=True,
                    timestamp__range=(
                        wallet_tx.timestamp - timedelta(seconds=60),
                        wallet_tx.timestamp + timedelta(seconds=60)
                    )
                ).first()
                
                if correct_stock_tx:
                    # Update both sides of the relationship
                    wallet_tx.stock_transaction = correct_stock_tx
                    wallet_tx.stock_transaction_id = correct_stock_tx.id
                    wallet_tx.save(update_fields=['stock_transaction', 'stock_transaction_id'])
                    
                    correct_stock_tx.wallet_transaction = wallet_tx
                    correct_stock_tx.save(update_fields=['wallet_transaction'])
                    
                    fixed_count += 1
                    logger.info(f"Fixed cross-user reference: Wallet TX {wallet_tx.id} now properly linked to Stock TX {correct_stock_tx.id} (same user {wallet_tx.user_id})")
                else:
                    logger.warning(f"Could not find a matching stock transaction for user {wallet_tx.user_id} to replace cross-user reference")
        
        return Response({
            "success": True, 
            "message": f"Fixed {fixed_count} transaction links out of {examined_count} examined"
        })
        
    except Exception as e:
        logger.error(f"Error fixing transaction links: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "error": str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

def fix_missing_wallet_link(stock_tx):
    """
    Try to fix a missing wallet_transaction link for a stock transaction.
    Returns True if a fix was applied.
    """
    if stock_tx.wallet_transaction is None:
        # Method 1: Try to find wallet transaction by stock_transaction reverse relationship
        wallet_tx = WalletTransaction.objects.filter(stock_transaction=stock_tx).first()
        if wallet_tx:
            # Use the utility function to ensure consistent bidirectional links
            stock_tx, wallet_tx = ensure_consistent_transaction_links(stock_tx, wallet_tx)
            logger.info(f"Fixed link between stock tx {stock_tx.id} and wallet tx {wallet_tx.id}")
            return True
            
        # Method 2: Look for a match with the same external_order_id
        if stock_tx.external_order_id:
            matching_tx = StockTransaction.objects.filter(
                external_order_id=stock_tx.external_order_id,
                user_id=stock_tx.user_id, 
                stock_id=stock_tx.stock_id,
                wallet_transaction__isnull=False
            ).exclude(id=stock_tx.id).first()
            
            if matching_tx and matching_tx.wallet_transaction:
                # Get the wallet transaction from the matching stock transaction
                wallet_tx = matching_tx.wallet_transaction
                
                # Use the utility function to create bidirectional links between stock_tx and wallet_tx
                stock_tx, wallet_tx = ensure_consistent_transaction_links(stock_tx, wallet_tx)
                logger.info(f"Fixed link for tx {stock_tx.id} using matching tx {matching_tx.id} with same external_order_id {stock_tx.external_order_id}")
                return True
                
        # Method 3: Try matching by time proximity
        return fix_transaction_link_by_time_proximity(stock_tx)
                
    return False

def fix_transaction_link_by_time_proximity(stock_tx):
    """
    Try to fix a missing wallet_transaction link by finding matching wallet transactions
    based on time proximity, user, and amount.
    """
    # Find transactions created within 1 second of this one for the same user/stock
    from datetime import timedelta

    time_window = 1  # seconds (more conservative)
    time_lower = stock_tx.timestamp - timedelta(seconds=time_window)
    time_upper = stock_tx.timestamp + timedelta(seconds=time_window)

    # For buy orders, wallet amount should be negative (debit)
    # For sell orders, wallet amount should be positive (credit)
    expected_is_debit = stock_tx.is_buy

    # Calculate the expected amount based on stock transaction
    expected_amount = stock_tx.quantity * stock_tx.price

    wallet_txs = WalletTransaction.objects.filter(
        user_id=stock_tx.user_id,
        timestamp__range=(time_lower, time_upper),
        is_debit=expected_is_debit,
        stock_transaction__isnull=True
    ).order_by('timestamp')

    # Find the closest match in time
    closest_wallet_tx = None
    smallest_time_diff = None

    for wallet_tx in wallet_txs:
        time_diff = abs((wallet_tx.timestamp - stock_tx.timestamp).total_seconds())
        amount_diff_percent = abs(abs(float(wallet_tx.amount)) - expected_amount) / expected_amount * 100 if expected_amount > 0 else 0
        
        # Only consider it if amount is reasonably close (within 5%)
        if amount_diff_percent <= 5:
            if smallest_time_diff is None or time_diff < smallest_time_diff:
                smallest_time_diff = time_diff
                closest_wallet_tx = wallet_tx

    if closest_wallet_tx:
        # Use the utility function to create bidirectional links
        stock_tx, closest_wallet_tx = ensure_consistent_transaction_links(stock_tx, closest_wallet_tx)
        logger.info(f"Fixed link between stock tx {stock_tx.id} and wallet tx {closest_wallet_tx.id} based on time proximity")
        return True
        
    return False

@api_view(['GET'])
@permission_classes([AllowAny])
def diagnose_transactions(request):
    """Diagnostic endpoint to examine transaction links"""
    try:
        # Get user ID and transaction IDs from the query parameters
        user_id = request.query_params.get('user_id')
        stock_tx_id = request.query_params.get('stock_tx_id')
        wallet_tx_id = request.query_params.get('wallet_tx_id')
        
        response_data = {
            "success": True,
            "diagnostics": {},
            "recommendations": []
        }
        
        # If we have a user ID, check all transactions for that user
        if user_id:
            stock_txs = StockTransaction.objects.filter(user_id=user_id).order_by('id')
            wallet_txs = WalletTransaction.objects.filter(user_id=user_id).order_by('id')
            
            response_data["diagnostics"]["user_info"] = {
                "user_id": user_id,
                "stock_transaction_count": stock_txs.count(),
                "wallet_transaction_count": wallet_txs.count()
            }
            
            # Include basic info about all stock transactions
            response_data["diagnostics"]["stock_transactions"] = [{
                "id": tx.id,
                "stock_id": tx.stock_id,
                "is_buy": tx.is_buy,
                "status": tx.status,
                "quantity": tx.quantity,
                "price": str(tx.price),
                "timestamp": tx.timestamp.isoformat(),
                "wallet_tx_id": tx.wallet_transaction_id if tx.wallet_transaction else None,
                "external_order_id": tx.external_order_id
            } for tx in stock_txs]
            
            # Include basic info about all wallet transactions
            response_data["diagnostics"]["wallet_transactions"] = [{
                "id": tx.id,
                "is_debit": tx.is_debit,
                "amount": str(tx.amount),
                "description": tx.description,
                "timestamp": tx.timestamp.isoformat(),
                "stock_id": tx.stock_id,
                "stock_tx_id": tx.stock_transaction_id
            } for tx in wallet_txs]
            
            # Check for missing and inconsistent links
            stock_tx_issues = []
            wallet_tx_issues = []
            
            for tx in stock_txs:
                if tx.wallet_transaction is None:
                    stock_tx_issues.append({
                        "id": tx.id,
                        "issue": "missing_wallet_link",
                        "details": f"Stock transaction {tx.id} has no wallet transaction link"
                    })
            
            for tx in wallet_txs:
                if tx.stock_id and tx.stock_transaction_id is None:
                    wallet_tx_issues.append({
                        "id": tx.id,
                        "issue": "missing_stock_link",
                        "details": f"Wallet transaction {tx.id} has a stock ID but no stock transaction link"
                    })
                elif tx.stock_transaction_id:
                    # Check if the stock transaction exists and belongs to this user
                    try:
                        stock_tx = StockTransaction.objects.get(id=tx.stock_transaction_id)
                        if stock_tx.user_id != int(user_id):
                            wallet_tx_issues.append({
                                "id": tx.id,
                                "issue": "cross_user_reference",
                                "details": f"Wallet transaction {tx.id} references stock transaction {tx.stock_transaction_id} belonging to user {stock_tx.user_id}"
                            })
                    except StockTransaction.DoesNotExist:
                        wallet_tx_issues.append({
                            "id": tx.id,
                            "issue": "invalid_stock_reference",
                            "details": f"Wallet transaction {tx.id} references non-existent stock transaction {tx.stock_transaction_id}"
                        })
            
            response_data["diagnostics"]["issues"] = {
                "stock_transaction_issues": stock_tx_issues,
                "wallet_transaction_issues": wallet_tx_issues
            }
            
            # Add recommendations if issues found
            if stock_tx_issues or wallet_tx_issues:
                response_data["recommendations"].append(
                    "Run fixTransactionLinks endpoint to resolve these issues"
                )
        
        # If specific stock transaction ID provided, get detailed info
        if stock_tx_id:
            try:
                stock_tx = StockTransaction.objects.get(id=stock_tx_id)
                response_data["diagnostics"]["specific_stock_tx"] = {
                    "id": stock_tx.id,
                    "user_id": stock_tx.user_id,
                    "stock_id": stock_tx.stock_id,
                    "is_buy": stock_tx.is_buy,
                    "status": stock_tx.status,
                    "quantity": stock_tx.quantity,
                    "price": str(stock_tx.price),
                    "timestamp": stock_tx.timestamp.isoformat(),
                    "wallet_tx_id": stock_tx.wallet_transaction_id if stock_tx.wallet_transaction else None,
                    "external_order_id": stock_tx.external_order_id
                }
                
                # Check if there are wallet transactions referencing this stock transaction
                wallet_references = WalletTransaction.objects.filter(stock_transaction_id=stock_tx_id)
                if wallet_references.exists():
                    response_data["diagnostics"]["specific_stock_tx"]["wallet_references"] = [{
                        "id": tx.id,
                        "user_id": tx.user_id,
                        "is_debit": tx.is_debit,
                        "amount": str(tx.amount),
                        "description": tx.description,
                        "timestamp": tx.timestamp.isoformat()
                    } for tx in wallet_references]
                    
                    # If cross-user reference found
                    for tx in wallet_references:
                        if tx.user_id != stock_tx.user_id:
                            response_data["recommendations"].append(
                                f"Fix cross-user reference: Wallet TX {tx.id} (user {tx.user_id}) references Stock TX {stock_tx.id} (user {stock_tx.user_id})"
                            )
            except StockTransaction.DoesNotExist:
                response_data["diagnostics"]["specific_stock_tx"] = {
                    "error": f"Stock transaction with ID {stock_tx_id} does not exist"
                }
        
        # If specific wallet transaction ID provided, get detailed info
        if wallet_tx_id:
            try:
                wallet_tx = WalletTransaction.objects.get(id=wallet_tx_id)
                response_data["diagnostics"]["specific_wallet_tx"] = {
                    "id": wallet_tx.id,
                    "user_id": wallet_tx.user_id,
                    "is_debit": wallet_tx.is_debit,
                    "amount": str(wallet_tx.amount),
                    "description": wallet_tx.description,
                    "timestamp": wallet_tx.timestamp.isoformat(),
                    "stock_id": wallet_tx.stock_id,
                    "stock_tx_id": wallet_tx.stock_transaction_id
                }
                
                # If wallet transaction has a stock transaction reference
                if wallet_tx.stock_transaction_id:
                    try:
                        stock_tx = StockTransaction.objects.get(id=wallet_tx.stock_transaction_id)
                        response_data["diagnostics"]["specific_wallet_tx"]["referenced_stock_tx"] = {
                            "id": stock_tx.id,
                            "user_id": stock_tx.user_id,
                            "stock_id": stock_tx.stock_id,
                            "is_buy": stock_tx.is_buy,
                            "status": stock_tx.status,
                            "quantity": stock_tx.quantity,
                            "price": str(stock_tx.price),
                            "timestamp": stock_tx.timestamp.isoformat(),
                            "wallet_tx_id": stock_tx.wallet_transaction_id if stock_tx.wallet_transaction else None
                        }
                        
                        # If cross-user reference found
                        if wallet_tx.user_id != stock_tx.user_id:
                            response_data["recommendations"].append(
                                f"Fix cross-user reference: Wallet TX {wallet_tx.id} (user {wallet_tx.user_id}) references Stock TX {stock_tx.id} (user {stock_tx.user_id})"
                            )
                            
                            # Look for a better stock transaction match
                            potential_matches = StockTransaction.objects.filter(
                                user_id=wallet_tx.user_id,
                                stock_id=stock_tx.stock_id,
                                wallet_transaction__isnull=True
                            ).order_by('timestamp')
                            
                            if potential_matches.exists():
                                response_data["recommendations"].append(
                                    f"Consider linking wallet transaction {wallet_tx.id} to stock transaction {potential_matches[0].id} (same user)"
                                )
                    except StockTransaction.DoesNotExist:
                        response_data["diagnostics"]["specific_wallet_tx"]["referenced_stock_tx"] = {
                            "error": f"Referenced stock transaction with ID {wallet_tx.stock_transaction_id} does not exist"
                        }
                        response_data["recommendations"].append(
                            f"Fix invalid stock transaction reference in wallet transaction {wallet_tx.id}"
                        )
            except WalletTransaction.DoesNotExist:
                response_data["diagnostics"]["specific_wallet_tx"] = {
                    "error": f"Wallet transaction with ID {wallet_tx_id} does not exist"
                }
        
        return Response(response_data)
    
    except Exception as e:
        logger.error(f"Error diagnosing transactions: {str(e)}")
        logger.error(traceback.format_exc())
        return Response(
            {"success": False, "error": str(e)}, 
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

# Add this new utility function
def ensure_consistent_transaction_links(stock_tx, wallet_tx):
    """
    Ensure consistent bidirectional links between stock transaction and wallet transaction.
    This utility function guarantees that both transactions point to each other correctly.
    
    Args:
        stock_tx: The StockTransaction object
        wallet_tx: The WalletTransaction object
    
    Returns:
        tuple: (stock_tx, wallet_tx) with consistent links established
    """
    # Log what we're trying to do for debugging
    logger.debug(f"Ensuring consistent bidirectional links between stock TX {stock_tx.id} and wallet TX {wallet_tx.id}")
    
    # Check if current links are already consistent
    current_stock_wallet_id = stock_tx.wallet_transaction_id if stock_tx.wallet_transaction else None
    current_wallet_stock_id = wallet_tx.stock_transaction_id
    
    if current_stock_wallet_id == wallet_tx.id and current_wallet_stock_id == stock_tx.id:
        logger.debug(f"Links already consistent between stock TX {stock_tx.id} and wallet TX {wallet_tx.id}")
        return stock_tx, wallet_tx
    
    # Log inconsistencies if any
    if current_stock_wallet_id != wallet_tx.id:
        logger.info(f"Fixing stock TX {stock_tx.id} wallet link: current={current_stock_wallet_id}, should be={wallet_tx.id}")
    
    if current_wallet_stock_id != stock_tx.id:
        logger.info(f"Fixing wallet TX {wallet_tx.id} stock link: current={current_wallet_stock_id}, should be={stock_tx.id}")
    
    # Update the stock transaction to point to the wallet transaction
    stock_tx.wallet_transaction = wallet_tx
    stock_tx.save(update_fields=['wallet_transaction'])
    
    # Update the wallet transaction to point to the stock transaction
    wallet_tx.stock_transaction = stock_tx
    wallet_tx.stock_transaction_id = stock_tx.id  # Explicitly set ID for consistency
    wallet_tx.save(update_fields=['stock_transaction', 'stock_transaction_id'])
    
    logger.info(f"Successfully established bidirectional link between stock TX {stock_tx.id} and wallet TX {wallet_tx.id}")
    
    return stock_tx, wallet_tx