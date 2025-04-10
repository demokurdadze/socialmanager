# social_manager/urls.py (or your main project urls.py)

from django.contrib import admin
from django.urls import path, include
from socialapp import views as socialapp_views

urlpatterns = [
    # Root URL
    path('', socialapp_views.root_redirect, name='root_redirect'),

    path('admin/', admin.site.urls),

    # Your App's core views
    path('home/', socialapp_views.home, name='home'),

    # Allauth URLs
    path('accounts/', include('allauth.urls')),

    # Meta Page Connection Flow URLs
    path('auth/meta/', socialapp_views.meta_auth, name='meta_auth'),
    path('auth/meta/callback/', socialapp_views.meta_callback, name='meta_callback'),

    # --- Webhook ---
    # Changed name for clarity if you like, ensure Meta Dev Portal points here
    path('webhook/messenger/', socialapp_views.messenger_webhook, name='messenger_webhook'),

    # --- REMOVE the grok_chat URL pattern ---
    # path('grok-chat/', socialapp_views.grok_chat, name='grok_chat'), # <<< REMOVE THIS LINE

    # --- AI Configuration and Testing URLs (Keep these) ---
    path('ai/prompt/', socialapp_views.update_system_prompt, name='update_system_prompt'),
    path('ai/test/', socialapp_views.test_ai_conversation, name='test_ai_conversation'),
    # API endpoint for the test chat AJAX calls (ensure path matches template fetch URL)
    path('ai/api/send_test_message/', socialapp_views.send_test_message, name='send_test_message'),

    # Add other app URLs if needed
]