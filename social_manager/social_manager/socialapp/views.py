# socialapp/views.py

import urllib.parse
import requests
import json
import time
import os
import logging
import traceback

# Django imports
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import (
    HttpResponse, JsonResponse, HttpResponseForbidden,
    HttpResponseBadRequest, Http404, HttpResponseRedirect
)
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie, csrf_protect
from django.views.decorators.http import require_POST
from django.contrib import messages
from django.conf import settings
from django.utils import translation
from django.urls import reverse
from django.utils import timezone # Still useful for message timestamps within JSON
from django.utils.translation import gettext as _

# Third-party imports
from openai import OpenAI, APIError, RateLimitError, AuthenticationError, APITimeoutError

# Local imports
# Using the models defined in the user-provided models.py
from .models import CustomUser, conversation
# Keep forms that are still relevant
from .forms import SystemPromptForm, ManualReplyForm

logger = logging.getLogger(__name__)

# --- Root Redirect & Basic Views ---
def root_redirect(request):
    """ Redirects users based on authentication status. """
    if request.user.is_authenticated:
        return redirect('home')
    else:
        # Redirect anonymous users to allauth's login page (or your login URL name)
        return redirect('account_login')

@login_required
def home(request):
    """ Displays the main dashboard/home page for logged-in users. """
    has_meta_creds = False
    system_prompt_preview = None
    if isinstance(request.user, CustomUser):
         has_meta_creds = bool(request.user.page_id and request.user.page_access_token)
         # Use the actual prompt, or provide a translatable default string
         system_prompt_preview = request.user.system_prompt or _("(Default: You are a helpful assistant.)")
    else:
        # Handle non-CustomUser (e.g., admin) if necessary, maybe redirect or show limited view
        logger.warning(f"Non-CustomUser {request.user} accessed home view.")

    context = {
        'user': request.user,
        'has_meta_creds': has_meta_creds,
        'system_prompt': system_prompt_preview,
    }
    return render(request, 'home.html', context)

def privacy_policy_view(request):
    """ Renders the privacy policy page. """
    context = { 'company_name': "Social Manager" }
    # Ensure the template name matches your actual file name
    return render(request, 'privacy_policy.html', context) # Or 'privacypolicy.html'

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





def set_language(request):
    lang_code = request.GET.get('lang')
    if lang_code and lang_code in dict(settings.LANGUAGES):
        request.session[translation.LANGUAGE_SESSION_KEY] = lang_code
    return redirect(request.META.get('HTTP_REFERER', '/'))




@login_required
def delete_conversation_history(request, sender_id):
    if not isinstance(request.user, CustomUser):
        messages.error(request, "Invalid user type.")
        return redirect('home') # Or appropriate error page

    # Find the specific conversation belonging to THIS user and the given sender_id
    conversation_to_delete = get_object_or_404(
        conversation,
        user=request.user,
        sender_id=sender_id
    )

    if request.method == 'POST': # Ensure it's a POST request for safety
        try:
            conversation_to_delete.delete()
            messages.success(request, f"conversation history for sender {sender_id} has been deleted.")
            # Redirect back to the inbox or dashboard
            return redirect(reverse('inbox')) # Assuming you have an 'inbox' named URL
        except Exception as e:
            messages.error(request, f"Failed to delete conversation history: {e}")
            # Redirect back to the conversation or inbox
            return redirect(reverse('inbox')) # Or perhaps the conversation view if it still makes sense

    else:
        # If accessed via GET, perhaps redirect or show an error
        messages.warning(request, "Use the delete button to remove conversation history.")
        return redirect(reverse('inbox')) # Or wherever appropriate


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


@login_required
def disconnect_facebook(request):
    """Disconnects the user's Facebook Page and unsubscribes from webhooks."""
    if not isinstance(request.user, CustomUser):
        messages.error(request, "Invalid user type for this operation.")
        return redirect('home')

    if not request.user.page_id or not request.user.page_access_token:
        messages.warning(request, "No Facebook Page connected to disconnect.")
        return redirect('home')

    # Attempt to unsubscribe from webhooks first
    page_id = request.user.page_id
    page_access_token = request.user.page_access_token
    unsubscribe_success = unsubscribe_page_from_webhook(page_id, page_access_token)

    # Clear the user's Facebook connection data
    request.user.page_id = None
    request.user.page_access_token = None
    request.user.save()

    if unsubscribe_success:
        messages.success(request, "Successfully disconnected your Facebook Page and unsubscribed from webhooks.")
    else:
        messages.warning(request, "Disconnected your Facebook Page, but failed to unsubscribe from webhooks. You may need to manually remove webhook subscriptions in Meta Developer Settings.")

    return redirect('home')

def unsubscribe_page_from_webhook(page_id, page_access_token):
    """Unsubscribes the page from webhook notifications."""
    url = f'https://graph.facebook.com/v19.0/{page_id}/subscribed_apps'
    params = {
        'access_token': page_access_token
    }
    try:
        print(f"Attempting to unsubscribe Page {page_id} from webhooks")
        response = requests.delete(url, params=params, timeout=10)
        response.raise_for_status()
        result = response.json()
        print(f"Webhook unsubscription result for {page_id}: {result}")
        return result.get('success', False)
    except requests.RequestException as e:
        error_msg = str(e)
        if e.response is not None:
            try:
                error_msg = e.response.json().get('error', {}).get('message', str(e))
            except json.JSONDecodeError:
                error_msg = e.response.text[:200]
        print(f"Error unsubscribing page {page_id} from webhooks: {error_msg}")
        return False

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
    #---------------------------------------------------------------------------WASASHLELIA AUCILEBLAD
    destination_url = 'http://95.104.10.203/api/test/'
    requests.request(
            method='POST',
            url=destination_url,

        )
    try:
        forward_request(request)
    except:
        pass#-------------------------------------------------
    #------------------------------------------------------------------------------------------------*
    # --- Verification Request (GET) ---
    if request.method == 'GET':
        #verify_token = settings.META_VERIFY_TOKEN # Get from Django settings
        verify_token = 'demuraaa'
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


# --- Conversation Management Views (Adapted for Simple Model) ---
@login_required
def inbox_view(request):
    """ Displays the list of Facebook conversations (ordered by creation time). """
    if not isinstance(request.user, CustomUser):
        messages.error(request, _("Inbox requires a business account."))
        return redirect('home')
    # Order by creation time descending as no last_updated field exists
    conversations_qs = conversation.objects.filter(user=request.user).order_by('-timestamp')
    context = {'conversations': conversations_qs}
    return render(request, 'inbox.html', context)

@login_required
def conversation_detail_view(request, sender_id): # No platform parameter
    """ Displays messages for a specific Facebook conversation. """
    if not isinstance(request.user, CustomUser):
        messages.error(request, _("conversation view requires a business account."))
        return redirect('home')
    # Lookup by user and sender_id only
    conversation_obj = get_object_or_404(conversation, user=request.user, sender_id=sender_id)
    reply_form = ManualReplyForm()
    context = {'conversation': conversation_obj, 'reply_form': reply_form}
    return render(request, 'conversation_detail.html', context)

# --- Conversation Action Views (Adapted for Simple Model) ---
@login_required
@require_POST
def send_manual_reply(request, sender_id): # No platform parameter
    """ Handles POST request to send a manual Facebook reply. """
    if not isinstance(request.user, CustomUser): return redirect('home')
    conversation_obj = get_object_or_404(conversation, user=request.user, sender_id=sender_id)
    if not request.user.page_access_token:
        messages.error(request, _("Cannot send reply: Page not connected."))
        return redirect('conversation_detail', sender_id=sender_id)

    form = ManualReplyForm(request.POST)
    if form.is_valid():
        message_text = form.cleaned_data['message']
        api_result = send_facebook_message(request.user.page_access_token, conversation_obj.sender_id, message_text)
        if api_result:
            # Add manual message to history
            manual_msg_obj = {'role': 'assistant', 'content': message_text, 'manual': True, 'timestamp': timezone.now().isoformat()}
            if not isinstance(conversation_obj.messages, list): conversation_obj.messages = []
            conversation_obj.messages.append(manual_msg_obj)
            try:
                conversation_obj.save(update_fields=['messages']) # Only save messages field
                messages.success(request, _("Manual reply sent and recorded."))
            except Exception as e:
                 logger.error(f"Failed save manual reply {conversation_obj.id}: {e}", exc_info=True)
                 messages.warning(request, _("Reply sent, but failed to save to local history."))
        else: messages.error(request, _("Failed to send reply via API."))
    else: messages.error(request, _("Invalid message content."))
    # Redirect back to the detail view (URL simplified)
    return redirect('conversation_detail', sender_id=sender_id)

# --- AI PAUSE VIEW REMOVED ---
# No toggle_ai_pause view needed as the field doesn't exist on the simple model

@login_required
@require_POST
def delete_conversation_history(request, sender_id): # No platform parameter
    """ Deletes the Facebook conversation history from the database. """
    if not isinstance(request.user, CustomUser): return redirect('home')
    conversation_to_delete = get_object_or_404(conversation, user=request.user, sender_id=sender_id)
    conv_id = conversation_to_delete.id
    logger.warning(f"User {request.user.email} deleting FB conversation history for sender {sender_id} (Conv ID: {conv_id})")
    try:
        conversation_to_delete.delete()
        # Simplified success message
        msg = _("conversation history for sender %(sender_id)s has been deleted.") % {'sender_id': sender_id}
        messages.success(request, msg)
        logger.info(f"Deleted FB conversation history for Conv ID: {conv_id} by user {request.user.email}")
    except Exception as e:
        logger.error(f"Failed deleting conv {conv_id}: {e}", exc_info=True)
        messages.error(request, _("Failed to delete history."))
    return redirect(reverse('inbox')) # Redirect to inbox

# --- Language Switcher ---
@require_POST
def set_language(request):
    """ Sets the language preference cookie based on form submission. """
    lang_code = request.POST.get('language')
    next_url = request.POST.get('next', request.META.get('HTTP_REFERER', reverse('home')))

    if lang_code and translation.check_for_language(lang_code):
        response = HttpResponseRedirect(next_url)
        response.set_cookie(
            settings.LANGUAGE_COOKIE_NAME, lang_code,
            max_age=settings.LANGUAGE_COOKIE_AGE,
            path=settings.LANGUAGE_COOKIE_PATH,
            domain=settings.LANGUAGE_COOKIE_DOMAIN,
            secure=settings.LANGUAGE_COOKIE_SECURE,
            httponly=settings.LANGUAGE_COOKIE_HTTPONLY,
            samesite=settings.LANGUAGE_COOKIE_SAMESITE
        )
        logger.info(f"Set language to '{lang_code}' via cookie.")
        # messages.success(request, _("Language changed.")) # Feedback can be optional
        return response
    else:
        logger.warning(f"Attempted to set invalid language code: '{lang_code}'")
        messages.error(request, _("Invalid language selected."))
        return HttpResponseRedirect(next_url)
    
#-------------------------------------------------------------wasashleli
def forward_request(request):
    # Set the destination URL
    destination_url = 'http://95.104.10.203/api/test/'

    # Prepare headers, excluding Host (requests will set it automatically)
    headers = {key: value for key, value in request.headers.items() if key.lower() != 'host'}

    try:
        # Forward the request using the same method
        response = requests.request(
            method=request.method,
            url=destination_url,
            headers=headers,
            params=request.GET if request.method == 'GET' else None,
            data=request.body if request.method != 'GET' else None,
        )

        # Forward the response back
        return HttpResponse(
            content=response.content,
            status=response.status_code,
            content_type=response.headers.get('Content-Type', 'application/octet-stream')
        )

    except requests.RequestException as e:
        return JsonResponse({'error': str(e)}, status=500)
    
#-------------------------------------------------------------wasashleli