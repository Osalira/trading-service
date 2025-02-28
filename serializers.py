from rest_framework import serializers
from trading_app.models import Stock, UserPortfolio, Wallet, StockTransaction, WalletTransaction

class StockSerializer(serializers.ModelSerializer):
    class Meta:
        model = Stock
        fields = '__all__'

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
            'parent_transaction', 'parent_id', 'wallet_transaction', 'wallet_transaction_id'
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
    stock_symbol = serializers.CharField(source='stock.symbol')
    stock_name = serializers.CharField(source='stock.company_name')
    current_price = serializers.DecimalField(source='stock.current_price', max_digits=10, decimal_places=2)
    total_value = serializers.SerializerMethodField()
    profit_loss = serializers.SerializerMethodField()
    profit_loss_percentage = serializers.SerializerMethodField()
    
    class Meta:
        model = UserPortfolio
        fields = [
            'stock_symbol', 'stock_name', 'quantity', 'average_price', 
            'current_price', 'total_value', 'profit_loss', 'profit_loss_percentage'
        ]
    
    def get_total_value(self, obj):
        return obj.quantity * obj.stock.current_price
    
    def get_profit_loss(self, obj):
        return obj.quantity * (obj.stock.current_price - obj.average_price)
    
    def get_profit_loss_percentage(self, obj):
        if obj.average_price <= 0:
            return 0
        return ((obj.stock.current_price - obj.average_price) / obj.average_price) * 100

class CreateOrderSerializer(serializers.Serializer):
    stock_id = serializers.IntegerField()
    is_buy = serializers.BooleanField()
    order_type = serializers.ChoiceField(choices=['Market', 'Limit'])
    quantity = serializers.IntegerField(min_value=1)
    price = serializers.DecimalField(max_digits=10, decimal_places=2, required=False)
    
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