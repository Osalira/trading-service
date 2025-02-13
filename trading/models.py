from django.db import models
from django.core.validators import MinValueValidator
from decimal import Decimal

class Wallet(models.Model):
    """
    Represents a user's trading wallet containing their balance and stocks
    """
    user_id = models.IntegerField(unique=True)  # References user from auth service
    balance = models.DecimalField(
        max_digits=15, 
        decimal_places=2,
        default=0.00,
        validators=[MinValueValidator(Decimal('0.00'))]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Wallet for user {self.user_id}"

class Stock(models.Model):
    """
    Represents a stock that can be traded
    """
    symbol = models.CharField(max_length=10, unique=True)
    name = models.CharField(max_length=100)
    current_price = models.DecimalField(max_digits=10, decimal_places=2)
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.symbol} - {self.name}"

class StockHolding(models.Model):
    """
    Represents the stocks held by a user in their wallet
    """
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='holdings')
    stock = models.ForeignKey(Stock, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=0, validators=[MinValueValidator(0)])
    average_price = models.DecimalField(max_digits=10, decimal_places=2)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('wallet', 'stock')

    def __str__(self):
        return f"{self.wallet.user_id} - {self.stock.symbol}: {self.quantity}"

class Order(models.Model):
    """
    Represents a trading order (buy or sell)
    """
    class OrderType(models.TextChoices):
        BUY = 'BUY', 'Buy'
        SELL = 'SELL', 'Sell'

    class OrderStatus(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        COMPLETED = 'COMPLETED', 'Completed'
        CANCELLED = 'CANCELLED', 'Cancelled'
        FAILED = 'FAILED', 'Failed'

    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='orders')
    stock = models.ForeignKey(Stock, on_delete=models.CASCADE)
    order_type = models.CharField(max_length=4, choices=OrderType.choices)
    quantity = models.IntegerField(validators=[MinValueValidator(1)])
    price = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(
        max_length=10,
        choices=OrderStatus.choices,
        default=OrderStatus.PENDING
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.order_type} {self.quantity} {self.stock.symbol} @ {self.price}"

class Transaction(models.Model):
    """
    Represents a completed trading transaction
    """
    order = models.OneToOneField(Order, on_delete=models.CASCADE, related_name='transaction')
    executed_price = models.DecimalField(max_digits=10, decimal_places=2)
    executed_quantity = models.IntegerField()
    transaction_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    executed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Transaction for Order {self.order.id}" 