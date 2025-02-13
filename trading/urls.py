from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router and register viewsets
router = DefaultRouter()
router.register(r'wallets', views.WalletViewSet, basename='wallet')
router.register(r'stocks', views.StockViewSet, basename='stock')

# URL patterns for the trading app
urlpatterns = [
    # Include router URLs
    path('', include(router.urls)),
    
    # Custom endpoints
    path('orders/place/', views.place_order, name='place-order'),
    path('portfolio/', views.get_portfolio, name='get-portfolio'),
] 