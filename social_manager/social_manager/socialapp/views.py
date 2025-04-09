# socialapp/views.py

import urllib.parse
import requests
from social_manager import settings
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from . import views # Careful with this import if it's recursive
from openai import OpenAI
import json
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from .models import CustomUser,conversation
from django.http import JsonResponse
import time
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

# @csrf_exempt
# def messenger_webhook(request):
#     print(request)
#     if request.method == 'GET':
#         # Verification logic (same as before)
#         verify_token = 'demuraaa'
#         hub_verify_token = request.GET.get('hub.verify_token', '')
#         if hub_verify_token == verify_token:
#             return HttpResponse(request.GET.get('hub.challenge', ''))
#         return HttpResponse('Invalid token', status=403)

#     elif request.method == 'POST':
#         data = json.loads(request.body)
#         for entry in data.get('entry', []):
#             for event in entry.get('messaging', []):
#                 sender_id = event.get('sender', {}).get('id')
#                 if not sender_id:
#                     continue

#                 # Check if user exists or create a new one
#                 user, created = MessengerUser.objects.get_or_create(sender_id=sender_id)

#                 # Skip processing if user hasn't paid
#                 if not user.is_paid:
#                     return HttpResponse('OK')  # Or send a payment reminder

#                 # Process message fragments
#                 if 'message' in event:
#                     message_text = event['message'].get('text', '')
#                     cache_key = f'msg_{sender_id}'
#                     fragments = cache.get(cache_key, [])
#                     fragments.append(message_text)
#                     cache.set(cache_key, fragments, timeout=5)  # Short timeout
#                     # Schedule combining task
#                     from .tasks import combine_messages
#                     combine_messages.apply_async(args=[sender_id], countdown=2)
#                     print(message_text)
#                     print('---------------------------------')
#         return HttpResponse('OK')


#------------------------------------------------------------------------------------------------------------------------------  
def send_message_to_grok(message: str) -> str:
    """
    Send a message to Grok API and return the response.
    
    Args:
        message (str): The message to send to Grok
        
    Returns:
        str: Response from Grok API or error message
        
    Raises:
        requests.RequestException: If the API call fails
    """
    # API endpoint - replace with actual endpoint from your API documentation
    API_ENDPOINT = "https://api.xai.com/grok/v1/chat"  # This is hypothetical, use your actual endpoint
    
    # API key - store this in your settings.py or environment variables
    try:
        API_KEY = settings.GROK_API_KEY
    except AttributeError:
        return "Error: GROK_API_KEY not configured in settings.py"

    # Headers for the API request
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }

    # Payload for the API request
    payload = {
        "message": message,
        "model": "grok",  # Adjust based on your API documentation
        "max_tokens": 500,  # Adjust as needed
    }

    try:
        # Make the API request
        response = requests.post(
            API_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=10  # Add timeout to prevent hanging
        )
        
        # Check if request was successful
        response.raise_for_status()
        
        # Parse the JSON response
        data = response.json()
        
        # Adjust this based on actual API response structure
        return data.get("response", "No response received")
        
    except requests.Timeout:
        return "Error: Request to Grok API timed out"
    except requests.RequestException as e:
        return f"Error: Failed to connect to Grok API - {str(e)}"
    except json.JSONDecodeError:
        return "Error: Invalid response format from Grok API"


def grok_chat(request):
    if request.method == "POST":
        message = request.POST.get("message", "")
        if not message:
            return JsonResponse({"error": "No message provided"}, status=400)
            
        response = send_message_to_grok(message)
        return JsonResponse({"response": response})
    
    return JsonResponse({"error": "Method not allowed"}, status=405)
#------------------------------------------------------------------------------------------------------------------------------

def send_message_to_AI(message):
    XAI_API_KEY = os.getenv("XAI_API_KEY")
    client = OpenAI(
        api_key='xai-P2NKQUwEzPnmIg9FZCxkCHtX8rgwEmcRWAkjEcfHid64zYsmXPyFCzFoaxpNoN9fWmHo862RZZ3yBPOB',
        base_url="https://api.x.ai/v1",
    )
    messages = [
        {
            'role':'system',
        #----------this is a placeholder content it should be gotten from the database.
            'content': 'you are a sales person'},

    ]
    messages.append({'role':'user','content':message})

    completion = client.chat.completions.create(
        model="grok-2-latest",
        messages=messages,

    )
    
    messages.append({'role':'assistant','content':completion.choices[0].message.content})

    #MessengerUser.objects.get_or_create(sender_id=sender_id)
    #conversation.objects.get_or_create(sender_id)
    return completion.choices[0].message.content


@csrf_exempt
def messenger_webhook(request):
    if request.method == 'GET':
        verify_token = 'demuraaa'  # Should be stored securely
        hub_verify_token = request.GET.get('hub.verify_token', '')
        if hub_verify_token == verify_token:
            return HttpResponse(request.GET.get('hub.challenge', ''))
        return HttpResponse('Invalid token', status=403)

    elif request.method == 'POST':
        data = json.loads(request.body)
        for entry in data.get('entry', []):
            for event in entry.get('messaging', []):
                sender_id = event.get('sender', {}).get('id')
                recipient_id = event.get('recipient', {}).get('id')
                if not sender_id or not recipient_id:
                    continue

                try:
                    custom_user = CustomUser.objects.get(page_id=recipient_id)
                except CustomUser.DoesNotExist:
                    continue  # Or log error

                if not custom_user.is_paid:
                    continue  # Skip processing if user hasn't paid

                if 'message' in event:
                    message_text = event['message'].get('text', '')
                    if message_text:
                        response = send_message_to_AI(custom_user, sender_id, message_text)
                        # Send response back via Facebook API
                        send_facebook_message(custom_user.page_access_token, sender_id, response)

        return HttpResponse('OK')

# Helper function to send messages via Facebook API
def send_facebook_message(page_access_token, recipient_id, message):
    url = f'https://graph.facebook.com/v19.0/me/messages?access_token={page_access_token}'
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": message}
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code != 200:
            print(f"Error sending message: {response.text}")
    except Exception as e:
        print(f"Exception sending message: {str(e)}")
        
# def send_message_to_AI(custom_user, sender_id, message):
#     try:
#         conversation_obj = conversation.objects.get(user=custom_user, sender_id=sender_id)
#     except conversation.DoesNotExist:
#         # Initialize conversation with system prompt from CustomUser or default
#         if custom_user.system_prompt:
#             initial_messages = [{'role': 'system', 'content': custom_user.system_prompt}]
#         else:
#             initial_messages = [{'role': 'system', 'content': 'you are a sales person'}]
#         conversation_obj = conversation.objects.create(
#             user=custom_user,
#             sender_id=sender_id,
#             messages=initial_messages
#         )
    
#     current_messages = conversation_obj.messages
#     current_messages.append({'role': 'user', 'content': message})
    
#     XAI_API_KEY = os.getenv("XAI_API_KEY")
#     client = OpenAI(
#         #api_key=XAI_API_KEY,
#         api_key = 'xai-P2NKQUwEzPnmIg9FZCxkCHtX8rgwEmcRWAkjEcfHid64zYsmXPyFCzFoaxpNoN9fWmHo862RZZ3yBPOB',
#         base_url="https://api.x.ai/v1"
#     )
    
#     completion = client.chat.completions.create(
#         model="grok-2-latest",
#         messages=current_messages,
#     )
    
#     assistant_response = completion.choices[0].message.content
#     current_messages.append({'role': 'assistant', 'content': assistant_response})
    
#     conversation_obj.messages = current_messages
#     conversation_obj.save()
    
#     return assistant_response

def send_message_to_AI(custom_user, sender_id, message):
    try:
        conversation_obj = conversation.objects.get(user=custom_user, sender_id=sender_id)
    except conversation.DoesNotExist:
        # Start with the business’s prompt or default
        if custom_user.system_prompt:
            initial_messages = [{'role': 'system', 'content': custom_user.system_prompt}]
        else:
            initial_messages = [{'role': 'system', 'content': 'you are a sales person'}]
        conversation_obj = conversation.objects.create(
            user=custom_user,
            sender_id=sender_id,
            messages=initial_messages
        )
    
    current_messages = conversation_obj.messages
    current_messages.append({'role': 'user', 'content': message})
    
    XAI_API_KEY = os.getenv("XAI_API_KEY")
    client = OpenAI(
        api_key='xai-P2NKQUwEzPnmIg9FZCxkCHtX8rgwEmcRWAkjEcfHid64zYsmXPyFCzFoaxpNoN9fWmHo862RZZ3yBPOB',
        base_url="https://api.x.ai/v1"
    )
    
    completion = client.chat.completions.create(
        model="grok-2-latest",
        messages=current_messages,
    )
    
    assistant_response = completion.choices[0].message.content
    current_messages.append({'role': 'assistant', 'content': assistant_response})
    
    conversation_obj.messages = current_messages
    conversation_obj.save()
    
    return assistant_response

#------------------OTARA AMIS QVEVIT 2 FUNQCIA TU GINDA TRAKSHI MOTYANI ZEDEBI AR GAAFUCHO
@login_required
def test_ai_conversation(request):
    """
    Render a page where users can test their AI with their system_prompt.
    """
    if not isinstance(request.user, CustomUser):
        return render(request, 'error.html', {'error': 'Unauthorized user type'})
    
    custom_user = request.user
    context = {
        'system_prompt': custom_user.system_prompt or 'you are a sales person',
    }
    return render(request, 'test_ai_conversation.html', context)

@login_required
def send_test_message(request):
    """
    Handle POST requests to send a test message to the AI and return the response.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)
    
    if not isinstance(request.user, CustomUser):
        return JsonResponse({"error": "Unauthorized user type"}, status=401)
    
    custom_user = request.user
    message = request.POST.get("message", "")
    conversation_id = request.POST.get("conversation_id", "")  # Get from frontend
    if not message:
        return JsonResponse({"error": "No message provided"}, status=400)
    
    # If no conversation_id provided, start a new one with a unique sender_id
    if not conversation_id:
        conversation_id = f"test_{custom_user.id}_{int(time.time())}"  # Unique per session
    
    # Call the existing function to process the message
    response = send_message_to_AI(custom_user, conversation_id, message)
    
    return JsonResponse({"response": response, "conversation_id": conversation_id})

