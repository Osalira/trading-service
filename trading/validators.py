from decimal import Decimal
from rest_framework.exceptions import ValidationError
from .models import Stock, Wallet, Order, StockHolding

def validate_order_parameters(data, user):
    """
    Validates order parameters and returns validated data
    Raises ValidationError if validation fails
    """
    # Required fields validation
    required_fields = ['stock_id', 'order_type', 'quantity', 'is_buy']
    for field in required_fields:
        if field not in data:
            raise ValidationError({
                'success': False,
                'data': {
                    'error': f'Missing required field: {field}'
                }
            })
    
    # Validate stock exists
    try:
        stock = Stock.objects.get(id=data['stock_id'])
    except Stock.DoesNotExist:
        raise ValidationError({
            'success': False,
            'data': {
                'error': f'Stock with id {data["stock_id"]} does not exist'
            }
        })
    
    # Validate order type based on buy/sell action
    if data['is_buy'] and data['order_type'] != 'MARKET':
        raise ValidationError({
            'success': False,
            'data': {
                'error': 'Buy orders must be MARKET orders'
            }
        })
    if not data['is_buy'] and data['order_type'] != 'LIMIT':
        raise ValidationError({
            'success': False,
            'data': {
                'error': 'Sell orders must be LIMIT orders'
            }
        })
    
    # Validate quantity
    try:
        quantity = int(data['quantity'])
        if quantity <= 0:
            raise ValueError
    except (ValueError, TypeError):
        raise ValidationError({
            'success': False,
            'data': {
                'error': 'Quantity must be a positive integer'
            }
        })
    
    # Validate price for LIMIT orders (all sell orders)
    if not data['is_buy']:  # SELL
        if 'price' not in data:
            raise ValidationError({
                'success': False,
                'data': {
                    'error': 'Price is required for sell orders'
                }
            })
        try:
            price = Decimal(str(data['price']))
            if price <= 0:
                raise ValueError
        except (ValueError, TypeError, decimal.InvalidOperation):
            raise ValidationError({
                'success': False,
                'data': {
                    'error': 'Price must be a positive number'
                }
            })
    
    # Get or create wallet for the user
    wallet, _ = Wallet.objects.get_or_create(user_id=user.id)
    
    # Convert is_buy to order_type
    order_type = 'BUY' if data['is_buy'] else 'SELL'
    
    # Special handling for company accounts
    if user.account_type == 'company':
        if not data['is_buy']:  # SELL (always LIMIT order)
            # Check if this is a stock created by this company
            if stock.company_id == user.id:
                # Companies can sell their own created stock without restrictions
                # The quantity they specify will become the new available shares
                stock.shares_available = quantity
                stock.total_shares = max(stock.total_shares, quantity)
                # Set the limit price as the current price for company's own stock
                stock.current_price = Decimal(str(data['price']))
                stock.save()
                
                # Update the company's holding
                holding, _ = StockHolding.objects.get_or_create(
                    wallet=wallet,
                    stock=stock,
                    defaults={
                        'quantity': quantity,
                        'average_price': Decimal(str(data['price']))
                    }
                )
                holding.quantity = quantity
                holding.average_price = Decimal(str(data['price']))
                holding.save()
            else:
                # Companies can sell other stocks only if they have sufficient holdings
                holding = StockHolding.objects.filter(wallet=wallet, stock=stock).first()
                if not holding or holding.quantity < quantity:
                    raise ValidationError({
                        'success': False,
                        'data': {
                            'error': 'Insufficient stock holdings for sell order'
                        }
                    })
    else:
        # Regular user validation
        if data['is_buy']:  # BUY
            # Check if user has sufficient balance
            required_amount = Decimal(str(quantity)) * stock.current_price
            if wallet.balance < required_amount:
                raise ValidationError({
                    'success': False,
                    'data': {
                        'error': 'Insufficient balance for buy order'
                    }
                })
        else:  # SELL
            # Check if user has sufficient holdings
            holding = StockHolding.objects.filter(wallet=wallet, stock=stock).first()
            if not holding or holding.quantity < quantity:
                raise ValidationError({
                    'success': False,
                    'data': {
                        'error': 'Insufficient stock holdings for sell order'
                    }
                })
    
    return {
        'wallet': wallet,
        'stock': stock,
        'quantity': quantity,
        'order_type': order_type,
        'price': Decimal(str(data.get('price', stock.current_price)))
    } 