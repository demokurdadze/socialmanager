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
       path('set_language/', socialapp_views.set_language, name='set_language'),
          path('i18n/', include('django.conf.urls.i18n')),
    # API endpoint for the test chat AJAX calls (ensure path matches template fetch URL)
    path('ai/api/send_test_message/', socialapp_views.send_test_message, name='send_test_message'),
        path('disconnect-page/', socialapp_views.disconnect_facebook, name='disconnect-page'),
        path('privacy_policy/', socialapp_views.privacy_policy_view, name='privacy_policy'),



         path('ai/send_test/', socialapp_views.send_test_message, name='send_test_message'),

    # Conversation Management (Updated URLs with platform)
    path('inbox/', socialapp_views.inbox_view, name='inbox'),
   path('conversation/<str:sender_id>/', socialapp_views.conversation_detail_view, name='conversation_detail'), # CORRECT PATTERN
    path('conversation/<str:sender_id>/reply/', socialapp_views.send_manual_reply, name='send_manual_reply'), # CORRECT PATTERN
    path('conversation/<str:sender_id>/delete/', socialapp_views.delete_conversation_history, name='delete_conversation'), # CORRECT PATTERN
    # ... other urls ...

    # Add other app URLs if needed
]