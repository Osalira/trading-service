from decimal import Decimal
from rest_framework.exceptions import ValidationError
from .models import Stock, Wallet, Order, StockHolding

def validate_order_parameters(data, user):
    """
    Validates order parameters and returns validated data
    Raises ValidationError if validation fails
    """
    # Required fields validation
    required_fields = ['stock_id', 'is_buy', 'quantity']
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
    
    # Get or create wallet
    wallet, _ = Wallet.objects.get_or_create(user_id=user.id)
    
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
    
    # Determine order type based on is_buy flag
    order_type = 'BUY' if data['is_buy'] else 'SELL'
    
    # For sell orders, validate ownership and price
    if not data['is_buy']:
        # Validate price is provided for sell orders
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
        
        # Check if user owns the stock
        holding = StockHolding.objects.filter(
            wallet=wallet,
            stock=stock,
            quantity__gt=0  # Ensure they have a positive quantity
        ).first()
        
        if not holding:
            raise ValidationError({
                'stock_id': 'You can only sell stocks you own'
            })
        
        if holding.quantity < quantity:
            raise ValidationError({
                'stock_id': f'Insufficient shares. You own {holding.quantity} shares but trying to sell {quantity}'
            })
    else:
        # For buy orders, validate sufficient funds
        price = stock.current_price
        total_cost = Decimal(str(quantity)) * price
        
        if wallet.balance < total_cost:
            raise ValidationError({
                'success': False,
                'data': {
                    'error': 'Insufficient funds for purchase'
                }
            })
    
    return {
        'wallet': wallet,
        'stock': stock,
        'quantity': quantity,
        'order_type': order_type,
        'price': price
    } 