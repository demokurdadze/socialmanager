# social_manager/urls.py (or your main project urls.py)

from django.contrib import admin
from django.urls import path, include
# from django.contrib.auth import views as auth_views # Remove this
from socialapp import views as socialapp_views # Use an alias to avoid name clashes

urlpatterns = [
    # Root URL - Redirects based on auth status
    path('', socialapp_views.root_redirect, name='root_redirect'),

    path('admin/', admin.site.urls),

    # Your App's core views
    path('home/', socialapp_views.home, name='home'),
    

    # --- REMOVE Custom Auth URLs ---
    # path('register/', socialapp_views.register, name='register'),
    # path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    # path('logout/', auth_views.LogoutView.as_view(), name='logout'),

    # --- Allauth URLs ---
    # Provides /accounts/login/, /accounts/logout/, /accounts/signup/,
    # /accounts/password/reset/, /accounts/social/login/facebook/, etc.
    path('accounts/', include('allauth.urls')), # Make sure this line exists

    # --- Meta Page Connection Flow URLs (Keep these) ---
    path('auth/meta/', socialapp_views.meta_auth, name='meta_auth'),
    path('auth/meta/callback/', socialapp_views.meta_callback, name='meta_callback'),

    # --- Webhook and other API endpoints ---
    path("webhook/", socialapp_views.messenger_webhook, name='webhook'), # Ensure META points here
    path('grok-chat/', socialapp_views.grok_chat, name='grok_chat'),

    # Add other app URLs if needed
]

# Optional: Configure settings.py for redirects
# LOGIN_REDIRECT_URL = 'home'
# LOGOUT_REDIRECT_URL = 'account_login' # Or 'landing_page' or '/'
# ACCOUNT_LOGOUT_ON_GET = True # Allows logout via GET request for simplicity (less secure)