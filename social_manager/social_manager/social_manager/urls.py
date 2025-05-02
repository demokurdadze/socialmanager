# social_manager/urls.py (or your main project urls.py)

from django.contrib import admin
from django.urls import path, include
from socialapp import views
from django.views.i18n import JavaScriptCatalog

urlpatterns = [
    path('', views.root_redirect, name='root_redirect'),
    path('home/', views.home, name='home'),
    path('privacy-policy/', views.privacy_policy_view, name='privacy_policy'),
        path('accounts/', include('allauth.urls')),
    path('jsi18n/', JavaScriptCatalog.as_view(), name='javascript-catalog'),

    # --- Meta/Facebook Authentication ---
 path('auth/meta/', views.meta_auth, name='meta_auth'),
    path('auth/meta/callback/', views.meta_callback, name='meta_callback'), # Ensure this matches META_REDIRECT_URI path

    # --- Page Management ---
    path('pages/', views.connected_pages_list, name='connected_pages_list'),
    path('pages/<int:connected_page_pk>/configure/', views.configure_page, name='configure_page'),
    path('pages/<int:connected_page_pk>/disconnect/', views.disconnect_page, name='disconnect_page'), # POST only

    # --- Webhook ---
    path('webhook/', views.messenger_webhook, name='messenger_webhook'), # Ensure this matches webhook URL in Meta App settings

    # --- AI Testing ---
    path('test-ai/', views.test_ai_conversation, name='test_ai_conversation'),
    path('test-ai/send/', views.send_test_message, name='send_test_message'), # POST only AJAX

    # --- Inbox and Conversations (Updated URLs) ---
    path('inbox/', views.inbox_view, name='inbox'),
    # Note the URL structure: includes page PK and sender ID
    path('inbox/<int:connected_page_pk>/<str:sender_id>/', views.conversation_detail_view, name='conversation_detail'),
    path('inbox/<int:connected_page_pk>/<str:sender_id>/reply/', views.send_manual_reply, name='send_manual_reply'), # POST only
    path('inbox/<int:connected_page_pk>/<str:sender_id>/delete/', views.delete_conversation_history, name='delete_conversation'), # POST only

    # --- Language ---
    path('set-language/', views.set_language, name='set_language'), # POST only

    # --- Removed Old Prompt URL ---
    # path('update-prompt/', views.update_system_prompt, name='update_system_prompt'),
]
