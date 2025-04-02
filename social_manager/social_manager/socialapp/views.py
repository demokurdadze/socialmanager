
import urllib.parse
import requests
from social_manager import settings
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
from django.urls import path
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from . import views

import json
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from .models import MessengerUser

def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')  # Redirect to the login page after successful registration
    else:
        form = UserCreationForm()
    return render(request, 'registration/register.html', {'form': form})

@login_required
def home(request):
    return render(request, 'home.html')

@login_required
def meta_auth(request):
    params = {
        'client_id': settings.META_APP_ID,
        'redirect_uri': settings.META_REDIRECT_URI,
        'scope': 'pages_manage_engagement,pages_read_engagement,instagram_manage_messages,pages_messaging, instagram_manage_messages, pages_manage_metadata',
        'response_type': 'code',
    }
    oauth_url = 'https://www.facebook.com/v19.0/dialog/oauth?' + urllib.parse.urlencode(params)
    return redirect(oauth_url)

# def meta_callback(request):
#     code = request.GET.get('code')
    
#     # Handle errors (e.g., user denied permissions)
#     if 'error' in request.GET:
#         return render(request, 'error.html', {'error': request.GET.get('error_description')})
    
#     # Exchange code for access token
#     token_url = 'https://graph.facebook.com/v19.0/oauth/access_token'
#     params = {
#         'client_id': settings.META_APP_ID,
#         'client_secret': settings.META_APP_SECRET,
#         'redirect_uri': settings.META_REDIRECT_URI,
#         'code': code,
#     }
#     response = requests.get(token_url, params=params).json()
#     access_token = response.get('access_token')
    
#     # --- FIX: Store token correctly ---
#     if request.user.is_authenticated:
#         # Save to logged-in user (example using a Profile model)
#         request.user.meta_access_token = access_token
#         request.user.save()
#     else:
#         # Option 1: Redirect to login
#         return redirect('login')
#         # Option 2: Store token in session (temporary)
#         # request.session['meta_access_token'] = access_token
        
#     print(response)
    
#     return redirect('home')

def meta_callback(request):
    code = request.GET.get('code')
    
    # Handle errors
    if 'error' in request.GET:
        return render(request, 'error.html', {'error': request.GET.get('error_description')})
    
    # Exchange code for access token
    token_url = 'https://graph.facebook.com/v19.0/oauth/access_token'
    params = {
        'client_id': settings.META_APP_ID,
        'client_secret': settings.META_APP_SECRET,
        'redirect_uri': settings.META_REDIRECT_URI,
        'code': code,
    }
    response = requests.get(token_url, params=params).json()
    
    # Extract USER access token (not page token yet)
    user_access_token = response.get('access_token')
    
    # --- Get Page ID and Page Access Token ---
    try:
        # Get first page ID (modify if multiple pages)
        page_id = get_page_id(user_access_token)
        
        # Get PAGE ACCESS TOKEN (different from user token)
        url = f'https://graph.facebook.com/v19.0/{page_id}'
        params = {
            'fields': 'access_token',
            'access_token': user_access_token
        }
        page_info = requests.get(url, params=params).json()
        page_access_token = page_info['access_token']
        
        # --- Subscribe Page to Webhook ---
        subscription_result = subscribe_page_to_webhook(page_id, page_access_token)
        print("Subscription result:", subscription_result)  # Debug
        
    except Exception as e:
        return render(request, 'error.html', {'error': f'Failed to subscribe page: {str(e)}'})
    
    # --- Save tokens to user (example) ---
    if request.user.is_authenticated:
        request.user.page_id = page_id  # Add these fields to your CustomUser model
        request.user.page_access_token = page_access_token
        request.user.save()
    
    return redirect('home')

def subscribe_page_to_webhook(page_id, page_access_token):
    """
    Subscribe the page to the webhook for message events.
    """
    url = f'https://graph.facebook.com/v19.0/{page_id}/subscribed_apps'
    params = {
        'access_token': page_access_token,
        'subscribed_fields': 'messages,messaging_postbacks'  # Add other fields if needed
    }
    response = requests.post(url, params=params)
    print(response)
    return response.json()

def get_page_id(access_token):
    url = 'https://graph.facebook.com/v19.0/me/accounts'
    response = requests.get(url, params={'access_token': access_token}).json()
    return response['data'][0]['id']  # First Page ID


def get_conversations(access_token, page_id):
    url = f'https://graph.facebook.com/v19.0/{page_id}/conversations'
    params = {
        'fields': 'messages{message,from,created_time}',
        'access_token': access_token,
    }
    response = requests.get(url, params=params).json()
    return response['data']


def get_instagram_messages(access_token, page_id):
    # Get Instagram Business Account ID
    url = f'https://graph.facebook.com/v19.0/{page_id}'
    params = {
        'fields': 'instagram_business_account',
        'access_token': access_token,
    }
    ig_account_id = requests.get(url, params=params).json()['instagram_business_account']['id']

    # Fetch Instagram conversations
    url = f'https://graph.facebook.com/v19.0/{ig_account_id}/conversations'
    params = {
        'fields': 'messages{id,text,from,timestamp}',
        'access_token': access_token,
    }
    response = requests.get(url, params=params).json()
    return response['data']

@csrf_exempt
def messenger_webhook(request):
    print(request)
    if request.method == 'GET':
        # Verification logic (same as before)
        verify_token = 'demuraaa'
        hub_verify_token = request.GET.get('hub.verify_token', '')
        if hub_verify_token == verify_token:
            return HttpResponse(request.GET.get('hub.challenge', ''))
        return HttpResponse('Invalid token', status=403)

    elif request.method == 'POST':
        data = json.loads(request.body)
        for entry in data.get('entry', []):
            for event in entry.get('messaging', []):
                sender_id = event.get('sender', {}).get('id')
                if not sender_id:
                    continue

                # Check if user exists or create a new one
                user, created = MessengerUser.objects.get_or_create(sender_id=sender_id)

                # Skip processing if user hasn't paid
                if not user.is_paid:
                    return HttpResponse('OK')  # Or send a payment reminder

                # Process message fragments
                if 'message' in event:
                    message_text = event['message'].get('text', '')
                    cache_key = f'msg_{sender_id}'
                    fragments = cache.get(cache_key, [])
                    fragments.append(message_text)
                    cache.set(cache_key, fragments, timeout=5)  # Short timeout
                    # Schedule combining task
                    from .tasks import combine_messages
                    combine_messages.apply_async(args=[sender_id], countdown=2)
                    print(message_text)
                    print('---------------------------------')
        return HttpResponse('OK')