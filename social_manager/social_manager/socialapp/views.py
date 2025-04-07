# socialapp/views.py

import urllib.parse
import requests
from social_manager import settings
# REMOVE: from django.contrib.auth.forms import UserCreationForm # Not needed for register
from django.shortcuts import render, redirect
# REMOVE: from django.urls import path # Not needed in views.py
# REMOVE: from django.contrib.auth import views as auth_views # Not needed if using allauth URLs
from django.contrib.auth.decorators import login_required
from . import views # Careful with this import if it's recursive
from openai import OpenAI
import json
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from .models import MessengerUser
from django.http import JsonResponse
import os
# REMOVE: from .forms import CustomUserCreationForm # Not needed for register view


# --- REMOVE Custom Registration View ---
# def register(request):
#     if request.method == 'POST':
#         form = CustomUserCreationForm(request.POST)
#         if form.is_valid():
#             form.save()
#             return redirect('login') # Use allauth's login name: 'account_login'
#     else:
#         form = CustomUserCreationForm()
#     return render(request, 'registration/register.html', {'form': form}) # Use allauth template path: 'account/signup.html'

# --- NEW: Root Redirect View ---
def root_redirect(request):
    if request.user.is_authenticated:
        return redirect('home') # Redirect logged-in users to home
    else:
        # Redirect anonymous users to allauth's login page
        # Make sure 'account_login' is the correct name provided by allauth's urls
        return redirect('account_login')



@login_required
def home(request):
    # Check if the user has connected their Meta page
    # You might want to add a check here and prompt connection if needed
    # has_meta_creds = bool(request.user.page_id and request.user.page_access_token)
    # context = {'has_meta_creds': has_meta_creds}
    # return render(request, 'home.html', context)
    return render(request, 'home.html')

# --- Meta Page Connection Views (Keep These) ---
@login_required
def meta_auth(request):
    """ Initiates the OAuth flow to get *Page Management* permissions """
    params = {
        'client_id': settings.META_APP_ID,
        'redirect_uri': settings.META_REDIRECT_URI, # Ensure this matches Meta Dev settings for *this* specific flow
        # These scopes are for managing pages, different from user login scopes
        'scope': 'pages_manage_engagement,pages_read_engagement,instagram_manage_messages,pages_messaging, instagram_manage_messages, pages_manage_metadata',
        'response_type': 'code',
        'state': f'user_{request.user.id}' # Optional: Add state for security/tracking
    }
    oauth_url = 'https://www.facebook.com/v19.0/dialog/oauth?' + urllib.parse.urlencode(params)
    return redirect(oauth_url)

@login_required # Ensure user is logged into *your app* before processing callback
def meta_callback(request):
    """ Handles the callback after user grants *Page Management* permissions """
    code = request.GET.get('code')

    # Optional: Verify state parameter if you used one
    # received_state = request.GET.get('state')
    # expected_state = f'user_{request.user.id}'
    # if received_state != expected_state:
    #     return render(request, 'error.html', {'error': 'Invalid state parameter.'})

    # Handle errors
    if 'error' in request.GET:
        return render(request, 'error.html', {'error': request.GET.get('error_description')})

    # Exchange code for USER access token (short-lived usually)
    token_url = 'https://graph.facebook.com/v19.0/oauth/access_token'
    params = {
        'client_id': settings.META_APP_ID,
        'client_secret': settings.META_APP_SECRET,
        'redirect_uri': settings.META_REDIRECT_URI, # Must match the one used in meta_auth
        'code': code,
    }
    try:
        response = requests.get(token_url, params=params)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        token_data = response.json()
        user_access_token = token_data.get('access_token')
        if not user_access_token:
            raise ValueError("Access token not found in response.")

        # --- Get Page ID and Page Access Token ---
        page_id = get_page_id(user_access_token) # Assumes user has at least one page
        if not page_id:
             raise ValueError("Could not retrieve Page ID. User might not have granted page permissions or has no pages.")

        page_access_token = get_page_access_token(page_id, user_access_token)
        if not page_access_token:
            raise ValueError("Could not retrieve Page Access Token.")

        # --- Subscribe Page to Webhook ---
        subscription_result = subscribe_page_to_webhook(page_id, page_access_token)
        print("Subscription result:", subscription_result) # Debug
        if not subscription_result.get('success'):
             # Log the error in more detail if possible
             print("Webhook subscription failed:", subscription_result)
             # Decide if this is a critical error or just a warning
             # raise ValueError("Failed to subscribe page to webhook.") # Or just log and continue

        # --- Save tokens to the *currently logged-in Django user* ---
        # Ensure your CustomUser model has 'page_id' and 'page_access_token' fields
        # Make sure these fields can store potentially long tokens (use TextField if needed)
        request.user.page_id = page_id
        request.user.page_access_token = page_access_token
        request.user.save(update_fields=['page_id', 'page_access_token'])

        print(f"Successfully associated Page ID {page_id} with user {request.user.username}")
        return redirect('home') # Redirect to home page after successful connection

    except requests.RequestException as e:
        # Log the error e
        print(f"Error during Meta API call: {e}")
        return render(request, 'error.html', {'error': f'Network or API error during Meta callback: {str(e)}'})
    except (KeyError, IndexError, ValueError) as e:
        # Handle errors like missing data in response, no pages found, etc.
        print(f"Error processing Meta callback data: {e}")
        # Provide a user-friendly error message
        return render(request, 'error.html', {'error': f'Error processing Facebook data: {str(e)}. Please ensure you granted necessary permissions and have a Facebook Page.'})
    except Exception as e: # Catch any other unexpected errors
        # Log the full error traceback for debugging
        print(f"Unexpected error in meta_callback: {e}")
        return render(request, 'error.html', {'error': 'An unexpected error occurred.'})


def get_page_id(user_access_token):
    """ Gets the ID of the *first* page the user granted access to. """
    url = 'https://graph.facebook.com/v19.0/me/accounts'
    params = {'access_token': user_access_token}
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        if data and 'data' in data and len(data['data']) > 0:
            return data['data'][0]['id'] # Return the ID of the first page
        else:
            # Handle case where user has no pages or didn't grant permission
            print("No pages found or permission not granted.")
            return None
    except requests.RequestException as e:
        print(f"Error fetching page IDs: {e}")
        raise # Re-raise to be caught in meta_callback

def get_page_access_token(page_id, user_access_token):
    """ Gets a *Page* Access Token, which is needed for page-specific actions. """
    url = f'https://graph.facebook.com/v19.0/{page_id}'
    params = {
        'fields': 'access_token',
        'access_token': user_access_token # Use the user token to request the page token
    }
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        page_info = response.json()
        if 'access_token' in page_info:
            return page_info['access_token']
        else:
            print("Page access token not found in response.")
            return None
    except requests.RequestException as e:
        print(f"Error fetching page access token: {e}")
        raise # Re-raise


def subscribe_page_to_webhook(page_id, page_access_token):
    """ Subscribe the page to the webhook for message events. """
    url = f'https://graph.facebook.com/v19.0/{page_id}/subscribed_apps'
    params = {
        'access_token': page_access_token,
         # Ensure these fields match what your app is approved for
        'subscribed_fields': 'messages,messaging_postbacks,message_reads' # Example fields
    }
    try:
        response = requests.post(url, params=params)
        # Check if the subscription was successful - Facebook often returns a simple {'success': true}
        # It might return 200 OK even if fields weren't subscribed (e.g., missing permissions)
        # It's good practice to check the response content.
        response_data = response.json()
        if response.status_code == 200 and response_data.get('success'):
            print(f"Successfully subscribed page {page_id} to webhook fields.")
        else:
            print(f"Webhook subscription might have failed for page {page_id}. Status: {response.status_code}, Response: {response_data}")
        return response_data # Return the JSON response for checking success status
    except requests.RequestException as e:
        print(f"Error subscribing page to webhook: {e}")
        # Decide how to handle this: raise an error, return failure status?
        return {'success': False, 'error': str(e)}


# --- Messenger/Instagram/AI Views (Keep These) ---

def get_conversations(access_token, page_id):
    # ... (keep existing implementation) ...
    url = f'https://graph.facebook.com/v19.0/{page_id}/conversations'
    params = {
        'fields': 'messages{message,from,created_time}',
        'access_token': access_token,
    }
    response = requests.get(url, params=params).json()
    return response.get('data', []) # Safely return data or empty list


def get_instagram_messages(access_token, page_id):
    # ... (keep existing implementation, add error handling) ...
    try:
        # Get Instagram Business Account ID
        url = f'https://graph.facebook.com/v19.0/{page_id}'
        params = {
            'fields': 'instagram_business_account',
            'access_token': access_token,
        }
        ig_response = requests.get(url, params=params)
        ig_response.raise_for_status()
        ig_data = ig_response.json()

        if 'instagram_business_account' not in ig_data or not ig_data['instagram_business_account']:
            print(f"No Instagram Business Account linked to Page ID {page_id}")
            return [] # Or raise an error
        ig_account_id = ig_data['instagram_business_account']['id']

        # Fetch Instagram conversations
        url = f'https://graph.facebook.com/v19.0/{ig_account_id}/conversations'
        params = {
            # Adjust fields as needed, 'text' might be inside 'message' object
            'fields': 'messages{id,message,from,timestamp}',
            'platform': 'instagram', # Specify platform
            'access_token': access_token, # Use Page Access Token
        }
        conv_response = requests.get(url, params=params)
        conv_response.raise_for_status()
        conv_data = conv_response.json()
        return conv_data.get('data', []) # Safely return data or empty list
    except requests.RequestException as e:
        print(f"Error fetching Instagram messages: {e}")
        return [] # Return empty list on error
    except KeyError as e:
        print(f"Missing expected key in Instagram API response: {e}")
        return []


@csrf_exempt
def messenger_webhook(request):
    # ... (keep existing implementation but add more logging/error handling) ...
    if request.method == 'GET':
        # Verification logic
        verify_token = settings.META_WEBHOOK_VERIFY_TOKEN # Get from settings
        hub_mode = request.GET.get('hub.mode')
        hub_verify_token = request.GET.get('hub.verify_token')
        hub_challenge = request.GET.get('hub.challenge')

        if hub_mode == 'subscribe' and hub_verify_token == verify_token:
            print("Webhook verified!")
            return HttpResponse(hub_challenge, status=200)
        else:
            print("Webhook verification failed!")
            return HttpResponse('Invalid verification token or mode', status=403)

    elif request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            print("Webhook received:", json.dumps(data, indent=2)) # Log incoming data

            if data.get("object") == "page": # For Messenger
                for entry in data.get('entry', []):
                    for event in entry.get('messaging', []):
                        sender_id = event.get('sender', {}).get('id')
                        recipient_id = event.get('recipient', {}).get('id') # Your Page ID

                        if not sender_id or sender_id == recipient_id: # Ignore messages from the page itself
                            continue

                        # Find the Django user associated with this page
                        # You might need a more robust way if multiple users manage the same page
                        try:
                            # Assuming page_id is unique per user managing it via your app
                            django_user = MessengerUser.objects.get(page_id=recipient_id) # Or CustomUser if that holds page_id
                        except MessengerUser.DoesNotExist: # Or CustomUser.DoesNotExist
                             print(f"No user found managing page {recipient_id}")
                             continue # Skip if no user is configured for this page

                        # Check if the associated Django user has paid or is active
                        if not django_user.is_paid: # Or check your user status field
                            print(f"Ignoring message from {sender_id} for page {recipient_id} - User not paid/active.")
                            # Optionally send a message back about subscription status
                            continue

                        # Process message
                        if event.get('message'):
                            message_text = event['message'].get('text')
                            message_id = event['message'].get('mid') # Message ID

                            if message_text:
                                print(f"Received message from {sender_id} on page {recipient_id}: {message_text}")
                                # --- Trigger your AI processing logic ---
                                # Option 1: Use Celery task (as you had)
                                # from .tasks import process_incoming_message
                                # process_incoming_message.delay(sender_id, recipient_id, message_text, message_id)

                                # Option 2: Simple direct call (might delay response if AI is slow)
                                # ai_response = send_message_to_AI(message_text) # Your AI function
                                # send_messenger_reply(sender_id, ai_response, django_user.page_access_token) # Need a function to send reply

                                # Caching logic (if needed for message fragments)
                                cache_key = f'msg_{sender_id}'
                                fragments = cache.get(cache_key, [])
                                fragments.append(message_text)
                                cache.set(cache_key, fragments, timeout=10) # Slightly longer timeout?
                                print(f"Cached fragments for {sender_id}: {fragments}")
                                # Schedule combining task (if using fragment approach)
                                # from .tasks import combine_messages
                                # combine_messages.apply_async(args=[sender_id, recipient_id], countdown=5) # Pass recipient_id too

                        elif event.get('postback'):
                            # Handle postbacks (button clicks, etc.)
                            payload = event['postback'].get('payload')
                            print(f"Received postback from {sender_id} with payload: {payload}")
                            # Handle based on payload

                        elif event.get('read'):
                             # Handle message read receipts
                             print(f"Message read by {sender_id}")

            elif data.get("object") == "instagram": # For Instagram Messaging
                 for entry in data.get('entry', []):
                    for event in entry.get('messaging', []):
                        sender_id = event.get('sender', {}).get('id') # Instagram Scoped User ID (IGSID)
                        recipient_id = event.get('recipient', {}).get('id') # Your Instagram Account ID

                        if not sender_id or sender_id == recipient_id:
                             continue

                        # Find Django user based on the linked Page ID
                        # You'll need to map the Instagram Account ID back to a Page ID,
                        # or store the Instagram Account ID on your User model during setup.
                        # Let's assume you have user.instagram_account_id
                        # try:
                        #    django_user = CustomUser.objects.get(instagram_account_id=recipient_id)
                        # except CustomUser.DoesNotExist:
                        #    print(f"No user found managing Instagram account {recipient_id}")
                        #    continue
                        # if not django_user.is_paid: continue

                        # Process IG message
                        if event.get('message'):
                            message_text = event['message'].get('text')
                            message_id = event['message'].get('mid')
                            if message_text:
                                print(f"Received IG message from {sender_id} on account {recipient_id}: {message_text}")
                                # Trigger AI processing...
                                # ai_response = send_message_to_AI(message_text)
                                # send_instagram_reply(sender_id, ai_response, django_user.page_access_token) # Need function to send IG reply

            return HttpResponse('EVENT_RECEIVED', status=200)

        except json.JSONDecodeError:
            print("Error decoding webhook JSON")
            return HttpResponse('Invalid JSON', status=400)
        except Exception as e:
            print(f"Error processing webhook: {e}") # Log the error
            # Return OK to Meta to prevent webhook disabling, but log the issue
            return HttpResponse('Internal Server Error', status=200) # Or 500 if you want Meta to retry

# Placeholder for sending replies - Implement these!
# def send_messenger_reply(recipient_id, message_text, page_access_token):
#     url = f"https://graph.facebook.com/v19.0/me/messages?access_token={page_access_token}"
#     payload = {
#         "recipient": {"id": recipient_id},
#         "message": {"text": message_text},
#         "messaging_type": "RESPONSE"
#     }
#     try:
#         response = requests.post(url, json=payload)
#         response.raise_for_status()
#         print(f"Sent reply to Messenger {recipient_id}: {message_text}")
#     except requests.RequestException as e:
#         print(f"Error sending Messenger reply to {recipient_id}: {e}")

# def send_instagram_reply(recipient_id, message_text, page_access_token):
#     url = f"https://graph.facebook.com/v19.0/me/messages?access_token={page_access_token}"
#     payload = {
#         "recipient": {"id": recipient_id}, # IGSID
#         "message": {"text": message_text}
#     }
#     try:
#         response = requests.post(url, json=payload)
#         response.raise_for_status()
#         print(f"Sent reply to Instagram {recipient_id}: {message_text}")
#     except requests.RequestException as e:
#         print(f"Error sending Instagram reply to {recipient_id}: {e}")


def send_message_to_grok(message: str) -> str:
    # ... (keep existing implementation) ...
    pass # Replace pass with your actual Grok code

def grok_chat(request):
    # ... (keep existing implementation) ...
    pass # Replace pass with your actual Grok code

def send_message_to_AI(message):
    # ... (keep existing implementation, ensure API key is secure) ...
    XAI_API_KEY = os.getenv("XAI_API_KEY") # Good practice
    if not XAI_API_KEY:
        print("Error: XAI_API_KEY environment variable not set.")
        return "Error: AI service not configured."

    # Use the correct key name for OpenAI library if using XAI's compatible endpoint
    client = OpenAI(
        api_key=XAI_API_KEY,
        base_url="https://api.x.ai/v1",
    )
    # ... rest of your AI logic ...
    try:
        # Define system prompt based on user settings or defaults
        # user_profile = # Get user profile/settings related to the conversation context
        # system_content = user_profile.ai_system_prompt or 'You are a helpful assistant.'
        system_content = 'you are a sales person' # Placeholder

        messages = [
            {'role': 'system', 'content': system_content},
            {'role': 'user', 'content': message}
            # Add previous conversation history here if needed for context
        ]

        completion = client.chat.completions.create(
            model="grok-1.5-flash", # Or your preferred model "grok-1" etc. Use latest available/suitable
            messages=messages,
            # Add other parameters like temperature, max_tokens if needed
            # temperature=0.7,
            # max_tokens=500,
        )

        response_content = completion.choices[0].message.content
        # Log the interaction?
        # ConversationHistory.objects.create(user=..., user_message=message, ai_response=response_content)
        return response_content
    except Exception as e:
        print(f"Error calling AI API: {e}")
        return "Sorry, I encountered an error trying to respond."