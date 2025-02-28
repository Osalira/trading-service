from django.contrib import admin
from django.urls import path, include
import sys
import os

# Add the parent directory to sys.path if it's not already there
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

urlpatterns = [
    path('admin/', admin.site.urls),
    # Import the urls from the root directory
    path('', include('urls')),
] 