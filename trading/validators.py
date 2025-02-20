from decimal import Decimal
from rest_framework.exceptions import ValidationError
from .models import Stock, Wallet, Order

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
    
    # Validate order type
    valid_order_types = ['MARKET', 'LIMIT']
    if data['order_type'] not in valid_order_types:
        raise ValidationError({
            'success': False,
            'data': {
                'error': f'Invalid order type. Must be one of: {", ".join(valid_order_types)}'
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
    
    # Validate price for LIMIT orders
    if data['order_type'] == 'LIMIT':
        if 'price' not in data:
            raise ValidationError({
                'success': False,
                'data': {
                    'error': 'Price is required for LIMIT orders'
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
        if not data['is_buy']:  # SELL
            # Check if this is a stock created by this company
            if stock.company_id == user.id:
                # Companies can sell their own created stock without restrictions
                # The quantity they specify will become the new available shares
                stock.shares_available = quantity
                stock.total_shares = max(stock.total_shares, quantity)
                stock.save()
            else:
                # For stocks not created by this company, check available shares
                if stock.shares_available < quantity:
                    raise ValidationError({
                        'success': False,
                        'data': {
                            'error': 'Insufficient shares available'
                        }
                    })
        else:  # BUY
            # Check if company has sufficient funds
            required_funds = quantity * (data.get('price', stock.current_price))
            if wallet.balance < required_funds:
                raise ValidationError({
                    'success': False,
                    'data': {
                        'error': 'Insufficient funds'
                    }
                })
    else:  # Regular user account
        if data['is_buy']:  # BUY
            required_funds = quantity * (data.get('price', stock.current_price))
            if wallet.balance < required_funds:
                raise ValidationError({
                    'success': False,
                    'data': {
                        'error': 'Insufficient funds'
                    }
                })
        else:  # SELL
            stock_holding = wallet.stockholding_set.filter(stock=stock).first()
            if not stock_holding or stock_holding.quantity < quantity:
                raise ValidationError({
                    'success': False,
                    'data': {
                        'error': 'Insufficient stock quantity'
                    }
                })
    
    return {
        'stock': stock,
        'wallet': wallet,
        'quantity': quantity,
        'order_type': order_type,
        'price': Decimal(str(data.get('price', stock.current_price)))
    } 