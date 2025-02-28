from django.urls import path
from views import (
    get_stock_prices,
    get_stock_portfolio,
    get_stock_transactions,
    add_money_to_wallet,
    get_wallet_balance,
    get_wallet_transactions,
    create_stock,
    add_stock_to_user
)

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