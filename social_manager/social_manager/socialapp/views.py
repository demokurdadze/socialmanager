# socialapp/views.py

import urllib.parse
import requests
import json
import time
import os

# Django imports
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse, HttpResponseForbidden, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.core.cache import cache # Keep if using fragment caching elsewhere
from django.contrib import messages
from django.conf import settings # Use Django settings

# Third-party imports
from openai import OpenAI, APIError, RateLimitError, AuthenticationError, APITimeoutError # Import specific OpenAI errors

# Local imports
from .models import CustomUser, conversation
from .forms import SystemPromptForm


# --- Root Redirect View ---
def root_redirect(request):
    """ Redirects users based on authentication status. """
    if request.user.is_authenticated:
        return redirect('home')
    else:
        # Redirect anonymous users to allauth's login page
        return redirect('account_login') # Make sure this name matches your allauth urls


@login_required
def home(request):
    """ Displays the main dashboard/home page for logged-in users. """
    # Check if the user (assuming CustomUser) has connected their Meta page
    has_meta_creds = False
    if isinstance(request.user, CustomUser):
         has_meta_creds = bool(request.user.page_id and request.user.page_access_token)

    context = {
        'user': request.user,
        'has_meta_creds': has_meta_creds
        }
    return render(request, 'home.html', context)

# --- Meta Page Connection Views ---

@login_required
def meta_auth(request):
    """ Initiates the OAuth flow to connect a Facebook Page. """
    if not settings.META_APP_ID or not settings.META_REDIRECT_URI:
         messages.error(request, "Meta application details are not configured in settings.")
         return redirect('home')

    params = {
        'client_id': settings.META_APP_ID,
        'redirect_uri': settings.META_REDIRECT_URI,
        # Request necessary permissions
        'scope': ','.join([
            'pages_show_list', # Needed to list pages
            'pages_manage_engagement',
            'pages_read_engagement',
            'instagram_basic', # Needed for IG account ID
            'instagram_manage_messages',
            'pages_messaging', # For FB messages
            'pages_manage_metadata' # For subscribing webhooks
            ]),
        'response_type': 'code',
        # Add state parameter for CSRF protection
        # 'state': 'your_random_csrf_string' # Generate and verify this
    }
    oauth_url = 'https://www.facebook.com/v19.0/dialog/oauth?' + urllib.parse.urlencode(params)
    return redirect(oauth_url)


@login_required # Ensure callback requires login
def meta_callback(request):
    """ Handles the callback from Facebook after user authorization. """
    code = request.GET.get('code')

    # Handle errors returned by Facebook in the URL
    if 'error' in request.GET:
        error_desc = request.GET.get('error_description', 'Unknown error.')
        messages.error(request, f"Error during Meta authentication: {error_desc}")
        return redirect('home')

    if not code:
        messages.error(request, "Authorization code not found in callback.")
        return redirect('home')

    if not isinstance(request.user, CustomUser):
         messages.error(request, "Invalid user type for Meta connection.")
         return redirect('home') # Or a more specific error page

    # --- Exchange code for User Access Token ---
    token_url = 'https://graph.facebook.com/v19.0/oauth/access_token'
    params = {
        'client_id': settings.META_APP_ID,
        'client_secret': settings.META_APP_SECRET,
        'redirect_uri': settings.META_REDIRECT_URI,
        'code': code,
    }
    try:
        response = requests.get(token_url, params=params, timeout=10)
        response.raise_for_status() # Check for HTTP errors (4xx, 5xx)
        token_data = response.json()
        user_access_token = token_data.get('access_token')

        if not user_access_token:
            messages.error(request, "Failed to retrieve access token from Meta. Response missing token.")
            return redirect('home')

        # --- Get Page ID and Page Access Token ---
        page_id = get_first_page_id(user_access_token) # Helper function below
        if not page_id:
             messages.error(request, "Could not find a Facebook Page associated with your account or permission denied.")
             return redirect('home')

        # Check if this page is already connected by another user
        existing_user = CustomUser.objects.filter(page_id=page_id).exclude(pk=request.user.pk).first()
        if existing_user:
            messages.error(request, f"This Facebook Page (ID: {page_id}) is already connected by another user ({existing_user.username}).")
            return redirect('home')


        page_access_token = get_page_access_token(page_id, user_access_token) # Helper function below
        if not page_access_token:
            messages.error(request, "Failed to retrieve Page access token. Check permissions.")
            return redirect('home')

        # --- Subscribe Page to Webhook ---
        subscription_result = subscribe_page_to_webhook(page_id, page_access_token)
        print("Subscription result:", subscription_result) # Debug log
        if not subscription_result or not subscription_result.get('success'):
             # Warn but proceed, maybe user needs manual setup?
             messages.warning(request, f"Page connected, but failed to automatically subscribe to message webhooks. Please check app settings in Meta Developer Dashboard. Error: {subscription_result.get('error', 'Unknown')}")

        # --- Save tokens to the logged-in CustomUser ---
        request.user.page_id = page_id
        request.user.page_access_token = page_access_token
        # Optionally store user_access_token if needed for token refresh or other tasks
        # request.user.meta_access_token = user_access_token
        request.user.save()

        messages.success(request, f"Successfully connected Facebook Page (ID: {page_id})!")

    except requests.Timeout:
        messages.error(request, 'Request to Facebook timed out. Please try again.')
    except requests.RequestException as e:
        error_detail = str(e)
        if e.response is not None:
            try:
                error_detail = e.response.json().get('error', {}).get('message', str(e))
            except json.JSONDecodeError:
                error_detail = e.response.text[:200] # Show beginning of non-JSON error
        messages.error(request, f'Error communicating with Facebook: {error_detail}')
    except KeyError as e:
         messages.error(request, f'Unexpected response structure from Facebook: Missing key {str(e)}')
    except Exception as e: # Catch any other unexpected errors
        messages.error(request, f'An unexpected error occurred during Meta connection: {str(e)}')

    return redirect('home')


# --- Meta API Helper Functions ---

def get_first_page_id(user_access_token):
    """ Gets the ID of the first page the user granted access to. """
    url = 'https://graph.facebook.com/v19.0/me/accounts'
    params = {'access_token': user_access_token, 'fields': 'id,name'} # Ask for name for logging
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data and data.get('data'):
            first_page = data['data'][0]
            print(f"Found page: {first_page.get('name')} (ID: {first_page.get('id')})")
            return first_page.get('id')
        else:
            print("No pages found for this user token or insufficient permissions.")
            return None
    except requests.RequestException as e:
        print(f"Error fetching page list: {e}")
        return None
    except (KeyError, IndexError):
        print("Error parsing page list response.")
        return None

def get_page_access_token(page_id, user_access_token):
    """ Gets a long-lived Page Access Token for the given Page ID. """
    url = f'https://graph.facebook.com/v19.0/{page_id}'
    params = {
        'fields': 'access_token', # Request the page access token
        'access_token': user_access_token # Use the User token to make the request
    }
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        page_info = response.json()
        page_access_token = page_info.get('access_token')
        if page_access_token:
            print(f"Retrieved Page Access Token for Page ID: {page_id}")
            return page_access_token
        else:
            print(f"Could not retrieve Page Access Token for Page ID: {page_id}. Check permissions.")
            return None
    except requests.RequestException as e:
        print(f"Error fetching page access token for {page_id}: {e}")
        return None
    except KeyError:
        print(f"Error parsing page access token response for {page_id}.")
        return None


def subscribe_page_to_webhook(page_id, page_access_token):
    """ Subscribes the page to webhook fields like 'messages'. """
    url = f'https://graph.facebook.com/v19.0/{page_id}/subscribed_apps'
    params = {
        'access_token': page_access_token,
        'subscribed_fields': 'messages,messaging_postbacks' # Add 'instagram_manage_messages' if needed and permissions granted
    }
    try:
        print(f"Attempting to subscribe Page {page_id} to webhook fields: {params['subscribed_fields']}")
        response = requests.post(url, params=params, timeout=10)
        response.raise_for_status()
        result = response.json()
        print(f"Webhook subscription result for {page_id}: {result}")
        return result # Should return {'success': True} on success
    except requests.RequestException as e:
        error_msg = str(e)
        if e.response is not None:
             try:
                 error_msg = e.response.json().get('error', {}).get('message', str(e))
             except json.JSONDecodeError:
                 error_msg = e.response.text[:200]
        print(f"Error subscribing page {page_id} to webhook: {error_msg}")
        return {'success': False, 'error': error_msg}


# --- Webhook Handler ---

@csrf_exempt # Required as Meta does not send CSRF tokens
def messenger_webhook(request):
    """ Handles incoming webhook events from Meta (Facebook/Instagram). """

    # --- Verification Request (GET) ---
    if request.method == 'GET':
        verify_token = settings.META_VERIFY_TOKEN # Get from Django settings
        hub_mode = request.GET.get('hub.mode')
        hub_verify_token = request.GET.get('hub.verify_token')
        hub_challenge = request.GET.get('hub.challenge')

        if hub_mode == 'subscribe' and hub_verify_token == verify_token:
            print("Webhook verification successful!")
            return HttpResponse(hub_challenge, status=200)
        else:
            print(f"Webhook verification failed. Mode: {hub_mode}, Received Token: '{hub_verify_token}', Expected: '{verify_token}'")
            return HttpResponseForbidden('Invalid verification token')

    # --- Event Notification (POST) ---
    elif request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
        except json.JSONDecodeError:
            print("Webhook Error: Invalid JSON received")
            return HttpResponseBadRequest("Invalid JSON")

        # Process incoming events (simplified example focusing on messages)
        # Ref: https://developers.facebook.com/docs/messenger-platform/webhook-reference/message
        if data.get("object") == "page": # For Facebook Pages
            for entry in data.get("entry", []):
                page_id = entry.get("id") # The Page ID
                for event in entry.get("messaging", []):
                    sender_id = event.get("sender", {}).get("id") # Person messaging the page (PSID)
                    recipient_id = event.get("recipient", {}).get("id") # Page ID (should match page_id)

                    if not sender_id or not recipient_id:
                        print("Webhook Info: Skipping event with missing sender/recipient ID.")
                        continue

                    # Ensure the event is for the correct page (redundancy check)
                    if str(page_id) != str(recipient_id):
                         print(f"Webhook Warning: Mismatched entry Page ID ({page_id}) and recipient ID ({recipient_id}).")
                         # continue # Decide if you want to skip these

                    try:
                        # Find the CustomUser associated with the page that received the message
                        custom_user = CustomUser.objects.get(page_id=recipient_id)
                    except CustomUser.DoesNotExist:
                        # This page isn't managed by any user in our system
                        print(f"Webhook Info: No CustomUser found for page_id {recipient_id}. Ignoring message.")
                        continue # Important: stop processing if no owner

                    # Optional: Check payment status if implemented
                    # if not custom_user.is_paid:
                    #     print(f"Webhook Info: User {custom_user.username} (Page ID: {recipient_id}) is not paid. Skipping AI response.")
                    #     continue

                    # --- Process Actual Message ---
                    if "message" in event:
                        message_data = event["message"]
                        message_id = message_data.get("mid") # Unique message ID

                        # Skip echoes (messages sent BY the page itself)
                        if message_data.get("is_echo", False):
                            print(f"Webhook Info: Skipping echo message {message_id} for page {recipient_id}.")
                            continue

                        message_text = message_data.get("text")
                        if message_text:
                            print(f"Webhook Received: From PSID {sender_id} to Page {recipient_id} (User: {custom_user.username}): '{message_text}'")
                            try:
                                # Pass the CustomUser object to the AI function
                                response_text = send_message_to_AI(custom_user, sender_id, message_text)
                                if response_text:
                                    # Send the AI's response back to the user
                                    send_facebook_message(custom_user.page_access_token, sender_id, response_text)
                                else:
                                    print(f"AI function returned no response for message {message_id}.")
                            except Exception as e:
                                print(f"Error processing message {message_id} or sending AI response: {e}")
                                # Optionally send a generic error back to the user
                                # send_facebook_message(custom_user.page_access_token, sender_id, "Sorry, I encountered an error. Please try again later.")
                        else:
                            # Handle non-text messages (attachments, etc.) if needed
                            print(f"Webhook Info: Received non-text message {message_id} (e.g., attachment) from {sender_id}. Skipping AI processing.")

                    # Handle postbacks if needed
                    elif "postback" in event:
                         payload = event["postback"].get("payload")
                         print(f"Webhook Info: Received postback from {sender_id} with payload: {payload}")
                         # Add logic to handle postbacks (button clicks) if necessary

        # Add handling for object == "instagram" if needed later
        # elif data.get("object") == "instagram":
        #      pass # Process Instagram events similarly

        # Always return 'OK' response to Meta quickly
        return HttpResponse("EVENT_RECEIVED", status=200)

    else:
        # Method not allowed
        return HttpResponseForbidden("Method not allowed")


# --- Facebook Message Sending Helper ---

def send_facebook_message(page_access_token, recipient_psid, message_text):
    """ Sends a text message back to a user via the Messenger Send API. """
    url = f'https://graph.facebook.com/v19.0/me/messages'
    headers = {'Content-Type': 'application/json'}
    params = {'access_token': page_access_token}
    payload = {
        "recipient": {"id": recipient_psid},
        "message": {"text": message_text},
        "messaging_type": "RESPONSE" # Necessary for messages sent within 24 hours window
    }
    print(f"Sending FB Message API Call to PSID {recipient_psid}: '{message_text[:100]}...'")
    try:
        response = requests.post(url, params=params, headers=headers, json=payload, timeout=15)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        result = response.json()
        print(f"FB Message Sent Successfully. Response: {result}")
        return result
    except requests.Timeout:
        print(f"Error sending FB message to {recipient_psid}: Request timed out")
        return None
    except requests.RequestException as e:
        error_msg = str(e)
        status_code = e.response.status_code if e.response is not None else 'N/A'
        if e.response is not None:
             try:
                 error_data = e.response.json().get('error', {})
                 error_msg = f"Code {error_data.get('code')}: {error_data.get('message')} (Subcode: {error_data.get('error_subcode')})"
             except json.JSONDecodeError:
                 error_msg = e.response.text[:200] # Show beginning of non-JSON error
        print(f"Error sending FB message to {recipient_psid}: Status {status_code}, Error: {error_msg}")
        # Consider specific error handling (e.g., token expiry, permissions)
        return None
    except Exception as e:
         print(f"Unexpected exception sending FB message to {recipient_psid}: {str(e)}")
         return None


# --- AI Interaction Logic ---

def send_message_to_AI(custom_user, sender_id, message):
    """
    Manages conversation history and interacts with the Grok AI model,
    using the specific user's system prompt.
    """
    if not isinstance(custom_user, CustomUser):
        print("Error: send_message_to_AI called with invalid user object")
        return "Internal configuration error." # Avoid sending specific errors to end-user

    try:
        # Find or create the conversation record
        conversation_obj, created = conversation.objects.get_or_create(
            user=custom_user,
            sender_id=sender_id,
            defaults={'messages': []} # Initialize messages as empty list if created
        )
    except Exception as e:
        print(f"Database Error: Failed to get/create conversation for user {custom_user.id}, sender {sender_id}: {e}")
        return "Sorry, I encountered an internal error managing our conversation history."

    # Retrieve current message history
    current_messages = conversation_obj.messages if isinstance(conversation_obj.messages, list) else []

    # --- Apply System Prompt ---
    # Ensure system prompt is the first message, using the user's specific prompt
    system_content = custom_user.system_prompt or "You are a helpful assistant." # Sensible default
    if not current_messages or not any(msg.get('role') == 'system' for msg in current_messages):
        # If history is empty OR somehow lost the system prompt, prepend it.
        print(f"Prepending system prompt for user {custom_user.username}, sender {sender_id}: '{system_content[:100]}...'")
        current_messages.insert(0, {'role': 'system', 'content': system_content})
    elif current_messages[0].get('role') == 'system' and current_messages[0].get('content') != system_content:
        # If system prompt exists but changed, update it (optional, depends on desired behavior)
        print(f"Updating system prompt for user {custom_user.username}, sender {sender_id}.")
        current_messages[0]['content'] = system_content

    # Append the latest user message
    current_messages.append({'role': 'user', 'content': message})

    # --- Pruning (Optional but Recommended) ---
    # Keep conversation history from getting excessively long (limits token usage & cost)
    MAX_HISTORY_MESSAGES = 20 # Example: Keep last 10 user/assistant pairs + system prompt
    if len(current_messages) > MAX_HISTORY_MESSAGES:
        print(f"Pruning conversation history from {len(current_messages)} to ~{MAX_HISTORY_MESSAGES} messages.")
        # Keep the system prompt (index 0) and the latest messages
        current_messages = [current_messages[0]] + current_messages[-(MAX_HISTORY_MESSAGES -1):]

    # --- Call Grok/OpenAI API ---
    try:
      
     

        # Ensure the key is used securely, not hardcoded
        client = OpenAI(
            api_key='xai-P2NKQUwEzPnmIg9FZCxkCHtX8rgwEmcRWAkjEcfHid64zYsmXPyFCzFoaxpNoN9fWmHo862RZZ3yBPOB',
            base_url="https://api.x.ai/v1" # Make sure this is the correct endpoint
            # Consider adding timeout configuration: timeout=20.0
        )

        print(f"Sending {len(current_messages)} messages to Grok API for user {custom_user.username}, sender {sender_id}.")

        # Make the API call
        completion = client.chat.completions.create(
            model="grok-2-latest", # Or "grok-1.5-vision-preview", "grok-2-latest" - CHECK AVAILABLE MODELS
            messages=current_messages,
            # Optional parameters:
            # max_tokens=1024, # Limit response length
            # temperature=0.7, # Control randomness (0.0 to 1.0)
        )

        assistant_response = completion.choices[0].message.content
        print(f"Grok API Response received for sender {sender_id}.")

    # --- Handle Specific API Errors ---
    except AuthenticationError:
         print(f"CRITICAL ERROR: Grok API Authentication Failed. Check GROK_API_KEY.")
         # Log this error prominently for the admin
         return "Sorry, there's an issue connecting to the AI service (Authentication)."
    except RateLimitError:
         print(f"Grok API Rate Limit Exceeded for user {custom_user.username}.")
         # Maybe implement backoff or notify user/admin
         return "The AI service is currently busy, please try again in a moment."
    except APITimeoutError:
        print(f"Grok API request timed out for user {custom_user.username}, sender {sender_id}.")
        return "The AI service took too long to respond, please try again."
    except APIError as e: # Catch other generic API errors from OpenAI library
        print(f"Grok API Error for user {custom_user.username}, sender {sender_id}: {e}")
        return f"Sorry, there was an error communicating with the AI service (API Error: {e.status_code})."
    except Exception as e: # Catch any other unexpected errors during API call
        print(f"Unexpected Error during AI API call for user {custom_user.username}, sender {sender_id}: {e}")
        # Log the full traceback for debugging
        import traceback
        traceback.print_exc()
        return "Sorry, an unexpected error occurred while processing your request with the AI."

    # --- Save conversation and return response ---
    if assistant_response: # Only save if we got a valid response
        current_messages.append({'role': 'assistant', 'content': assistant_response})
        conversation_obj.messages = current_messages
        try:
            conversation_obj.save()
        except Exception as e:
             print(f"Database Error: Failed to save updated conversation for user {custom_user.id}, sender {sender_id}: {e}")
             # The response is already generated, but history saving failed. Decide how critical this is.

    return assistant_response


# --- AI Configuration and Testing Views ---

@login_required
def update_system_prompt(request):
    """ Allows logged-in CustomUser to update their system_prompt. """
    if not isinstance(request.user, CustomUser):
        messages.error(request, "This feature is only available for business accounts.")
        return redirect('home') # Or appropriate error page

    custom_user = request.user # Get the logged-in CustomUser

    if request.method == 'POST':
        form = SystemPromptForm(request.POST, instance=custom_user)
        if form.is_valid():
            form.save() # Saves the prompt to the user's record
            messages.success(request, 'AI system prompt updated successfully!')
            return redirect('update_system_prompt') # Redirect back to the same page to see changes
        else:
            # Form validation failed
            messages.error(request, 'Please correct the errors in the form below.')
    else:
        # GET request: Show the form pre-filled with the current prompt
        form = SystemPromptForm(instance=custom_user)

    context = {
        'form': form,
        'current_prompt': custom_user.system_prompt # Pass current prompt for display
    }
    return render(request, 'update_system_prompt.html', context)


@login_required
@ensure_csrf_cookie # Ensures the CSRF cookie is set for the template's AJAX request
def test_ai_conversation(request):
    """ Renders the page for users to test their AI configuration. """
    if not isinstance(request.user, CustomUser):
        messages.error(request, 'This feature requires a business account.')
        return redirect('home')

    custom_user = request.user
    context = {
        # Provide the current prompt or the default text if none is set
        'system_prompt': custom_user.system_prompt or '(Default: You are a helpful assistant.)',
    }
    return render(request, 'test_ai_conversation.html', context)


@login_required
def send_test_message(request):
    """
    Handles AJAX POST requests from the AI test page.
    Sends the user's test message to the AI using their configuration.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    if not isinstance(request.user, CustomUser):
        return JsonResponse({"error": "Unauthorized user type"}, status=401)

    custom_user = request.user

    try:
        # Expecting JSON data in the request body from fetch API
        data = json.loads(request.body.decode('utf-8'))
        message = data.get("message", "").strip()
    except json.JSONDecodeError:
         return JsonResponse({"error": "Invalid JSON data in request body"}, status=400)
    except Exception as e:
        print(f"Error parsing test message request body: {e}")
        return JsonResponse({"error": "Error parsing request data"}, status=400)

    if not message:
        return JsonResponse({"error": "Message cannot be empty"}, status=400)

    # Use a dedicated sender_id for testing to keep test conversations separate
    # from real user conversations. Can be unique per test session if needed.
    test_sender_id = f"test_sender__{custom_user.id}"

    # Call the main AI function, passing the logged-in user and test sender ID
    try:
        response_text = send_message_to_AI(custom_user, test_sender_id, message)
        if response_text is None: # Handle cases where send_message_to_AI returns None on error
             return JsonResponse({"error": "AI service failed to generate a response."}, status=500)

        return JsonResponse({"response": response_text}) # Send the AI's reply back to the frontend

    except Exception as e:
        # Catch any unexpected errors during the call to send_message_to_AI
        print(f"Error in send_test_message view for user {custom_user.id}: {e}")
        # Log the full traceback
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": "An unexpected server error occurred while getting the AI response."}, status=500)