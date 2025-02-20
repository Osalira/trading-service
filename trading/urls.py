from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router and register viewsets
router = DefaultRouter()
router.register(r'wallets', views.WalletViewSet, basename='wallet')
router.register(r'stocks', views.StockViewSet, basename='stock')
router.register(r'orders', views.OrderViewSet, basename='order')

# URL patterns for the trading app
urlpatterns = [
    # Custom endpoints
    path('stocks/create/', views.create_stock, name='create_stock'),
    path('orders/place/', views.place_order, name='place-order'),
    path('orders/list/', views.get_orders, name='get-orders'),
    path('portfolio/', views.get_portfolio, name='get-portfolio'),
    path('stocks/company/', views.get_company_stocks, name='get_company_stocks'),
    path('stocks/add-to-user/', views.add_stock_to_user, name='add_stock_to_user'),
    path('stocks/portfolio/', views.get_stock_portfolio, name='get_stock_portfolio'),
    path('stocks/order/', views.place_stock_order, name='place_stock_order'),
    path('stocks/cancel-transaction/', views.cancel_stock_transaction, name='cancel_stock_transaction'),
    path('stocks/prices/', views.get_stock_prices, name='get_stock_prices'),
    path('wallet/add-money/', views.add_money_to_wallet, name='add_money_to_wallet'),
    path('wallet/balance/', views.get_wallet_balance, name='get_wallet_balance'),
    
    # Include router URLs last
    path('', include(router.urls)),
] 