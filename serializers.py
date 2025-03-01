from rest_framework import serializers
from trading_app.models import Stock, UserPortfolio, Wallet, StockTransaction, WalletTransaction

class StockSerializer(serializers.ModelSerializer):
    stock_name = serializers.CharField(required=False, write_only=True)
    
    class Meta:
        model = Stock
        fields = '__all__'
        extra_kwargs = {
            'symbol': {'required': False},
            'company_name': {'required': False},
            'current_price': {'required': False},
            'total_shares': {'required': False},
            'available_shares': {'required': False},
        }
    
    def validate(self, data):
        # Map stock_name to company_name if provided
        if 'stock_name' in data and not data.get('company_name'):
            data['company_name'] = data.pop('stock_name')
            
        # Generate a symbol if not provided based on company name
        if not data.get('symbol') and data.get('company_name'):
            # Use first 4 letters of company name (uppercase) as symbol
            company_name = data.get('company_name', '')
            symbol = ''.join(c for c in company_name if c.isalnum())[:4].upper()
            data['symbol'] = symbol
            
        # Ensure we have required fields either directly or derived
        if not data.get('company_name'):
            raise serializers.ValidationError({'company_name': 'Company name is required, either as company_name or stock_name'})
            
        # Remove price validation
        # Pricing will be determined by market orders through the matching engine
            
        return data

class UserPortfolioSerializer(serializers.ModelSerializer):
    stock_symbol = serializers.CharField(source='stock.symbol', read_only=True)
    stock_name = serializers.CharField(source='stock.company_name', read_only=True)
    current_price = serializers.DecimalField(source='stock.current_price', max_digits=10, decimal_places=2, read_only=True)
    total_value = serializers.SerializerMethodField()
    
    class Meta:
        model = UserPortfolio
        fields = [
            'id', 'user_id', 'stock', 'stock_symbol', 'stock_name', 
            'quantity', 'average_price', 'current_price', 'total_value', 
            'created_at', 'updated_at'
        ]
    
    def get_total_value(self, obj):
        if obj.stock.current_price is None:
            return 0  # Return 0 if current_price is None
        return obj.quantity * obj.stock.current_price

class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = '__all__'

class StockTransactionSerializer(serializers.ModelSerializer):
    stock_symbol = serializers.CharField(source='stock.symbol', read_only=True)
    parent_id = serializers.IntegerField(source='parent_transaction.id', read_only=True, allow_null=True)
    wallet_transaction_id = serializers.IntegerField(source='wallet_transaction.id', read_only=True, allow_null=True)
    
    class Meta:
        model = StockTransaction
        fields = [
            'id', 'user_id', 'stock', 'stock_symbol', 'is_buy', 
            'order_type', 'status', 'quantity', 'price', 'timestamp',
            'parent_transaction', 'parent_id', 'wallet_transaction', 'wallet_transaction_id',
            'external_order_id'
        ]
        read_only_fields = ['id', 'timestamp', 'wallet_transaction', 'wallet_transaction_id']

class WalletTransactionSerializer(serializers.ModelSerializer):
    stock_symbol = serializers.CharField(source='stock.symbol', read_only=True, allow_null=True)
    
    class Meta:
        model = WalletTransaction
        fields = [
            'id', 'user_id', 'stock', 'stock_symbol', 'stock_transaction_id',
            'is_debit', 'amount', 'description', 'timestamp'
        ]
        read_only_fields = ['id', 'timestamp']

# Serializers for specific API responses

class StockPriceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Stock
        fields = ['id', 'symbol', 'company_name', 'current_price', 'updated_at']

class PortfolioResponseSerializer(serializers.ModelSerializer):
    stock_id = serializers.CharField(source='stock.id')
    stock_symbol = serializers.CharField(source='stock.symbol')
    stock_name = serializers.CharField(source='stock.company_name')
    current_price = serializers.DecimalField(source='stock.current_price', max_digits=10, decimal_places=2)
    average_price = serializers.DecimalField(max_digits=10, decimal_places=2)
    quantity_owned = serializers.IntegerField(source='quantity')
    total_value = serializers.SerializerMethodField()
    profit_loss = serializers.SerializerMethodField()
    profit_loss_percentage = serializers.SerializerMethodField()
    has_pending_sells = serializers.SerializerMethodField()
    pending_sell_quantity = serializers.SerializerMethodField()
    available_quantity = serializers.SerializerMethodField()
    transaction_status = serializers.SerializerMethodField()
    transaction_id = serializers.SerializerMethodField()
    external_order_id = serializers.SerializerMethodField()
    
    class Meta:
        model = UserPortfolio
        fields = ['stock_id', 'stock_name', 'stock_symbol', 'current_price', 
                  'average_price', 'quantity_owned', 'total_value', 
                  'profit_loss', 'profit_loss_percentage',
                  'has_pending_sells', 'pending_sell_quantity', 'available_quantity',
                  'transaction_status', 'transaction_id', 'external_order_id']
    
    def get_total_value(self, obj):
        if obj.stock.current_price is None:
            return 0
        return obj.quantity * obj.stock.current_price
    
    def get_profit_loss(self, obj):
        if obj.stock.current_price is None or obj.average_price is None:
            return 0
        return obj.quantity * (obj.stock.current_price - obj.average_price)
    
    def get_profit_loss_percentage(self, obj):
        if obj.average_price is None or obj.average_price <= 0 or obj.stock.current_price is None:
            return 0
        return ((obj.stock.current_price - obj.average_price) / obj.average_price) * 100
    
    def get_has_pending_sells(self, obj):
        # Get from custom attribute set in view, or calculate from context
        if hasattr(obj, 'has_pending_sells'):
            return obj.has_pending_sells
        
        # Fallback to context
        pending_sells = self.context.get('pending_sells', {})
        # Ensure we're using the correct key type - stock_id might be an int or str
        stock_id = obj.stock.id
        pending_quantity = pending_sells.get(stock_id, 0)
        if pending_quantity == 0 and str(stock_id) in pending_sells:
            pending_quantity = pending_sells.get(str(stock_id), 0)
        return pending_quantity > 0
    
    def get_pending_sell_quantity(self, obj):
        # Get from custom attribute set in view, or calculate from context
        if hasattr(obj, 'pending_sell_quantity'):
            return obj.pending_sell_quantity
        
        # Fallback to context
        pending_sells = self.context.get('pending_sells', {})
        # Ensure we're using the correct key type - stock_id might be an int or str
        stock_id = obj.stock.id
        pending_quantity = pending_sells.get(stock_id, 0)
        if pending_quantity == 0 and str(stock_id) in pending_sells:
            pending_quantity = pending_sells.get(str(stock_id), 0)
        return pending_quantity
    
    def get_available_quantity(self, obj):
        # Calculate available quantity (total - pending sells)
        pending_quantity = self.get_pending_sell_quantity(obj)
        total_quantity = obj.quantity
        return max(0, total_quantity - pending_quantity)
        
    def get_transaction_status(self, obj):
        # Get transaction status from the object attribute if available
        if hasattr(obj, 'transaction_status'):
            return obj.transaction_status
        
        # Fallback to context
        transaction_status = self.context.get('transaction_status', {})
        return transaction_status.get(obj.stock_id, {}).get('status')
    
    def get_transaction_id(self, obj):
        # Get transaction ID from the object attribute if available
        if hasattr(obj, 'transaction_id'):
            return obj.transaction_id
        
        # Fallback to context
        transaction_status = self.context.get('transaction_status', {})
        return transaction_status.get(obj.stock_id, {}).get('transaction_id')
    
    def get_external_order_id(self, obj):
        # Get external order ID from the object attribute if available
        if hasattr(obj, 'external_order_id'):
            return obj.external_order_id
        
        # Fallback to context
        transaction_status = self.context.get('transaction_status', {})
        return transaction_status.get(obj.stock_id, {}).get('external_order_id')

class CreateOrderSerializer(serializers.Serializer):
    stock_id = serializers.IntegerField()
    is_buy = serializers.BooleanField()
    order_type = serializers.ChoiceField(choices=['Market', 'Limit'])
    quantity = serializers.IntegerField(min_value=1)
    price = serializers.DecimalField(max_digits=10, decimal_places=2, required=False)
    external_order_id = serializers.IntegerField(required=False, allow_null=True)
    
    def validate(self, data):
        if data['order_type'] == 'Limit' and 'price' not in data:
            raise serializers.ValidationError({"price": "Price is required for limit orders"})
        return data

class CancelOrderSerializer(serializers.Serializer):
    transaction_id = serializers.IntegerField()

class AddMoneySerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=12, decimal_places=2, min_value=0.01)

class WalletBalanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['user_id', 'balance'] 