from django.utils import translation 
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
from django.views.decorators.http import require_POST, require_GET # Added require_GET
from django.contrib import messages
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _, gettext_lazy
from django.db import transaction # For atomic operations
from django.db import models as db_models
# Third-party imports
from openai import OpenAI, APIError, RateLimitError, AuthenticationError, APITimeoutError

# Local imports
# Use the updated models and forms
from .models import CustomUser, ConnectedPage, conversation
from .forms import ManualReplyForm, PageSystemPromptForm # Use the new PageSystemPromptForm


logger = logging.getLogger(__name__)

# --- Root Redirect & Basic Views ---
def root_redirect(request):
    """ Redirects users based on authentication status. """
    if request.user.is_authenticated:
        # Redirect to a page listing connected pages if they exist, else home
        if ConnectedPage.objects.filter(user=request.user).exists():
            return redirect('connected_pages_list')
        else:
            return redirect('home') # Home can guide them to connect
    else:
        return redirect('account_login')

@login_required
def home(request):
    """ Displays the main dashboard/home page for logged-in users. """
    # Check if the user has *any* connected pages
    connected_pages = ConnectedPage.objects.filter(user=request.user)
    has_connected_pages = connected_pages.exists()

    context = {
        'user': request.user,
        'has_connected_pages': has_connected_pages,
        'connected_pages_count': connected_pages.count(),
        # No longer need a single system_prompt preview here
    }
    return render(request, 'home.html', context)

def privacy_policy_view(request):
    """ Renders the privacy policy page. """
    context = { 'company_name': "Social Manager" }
    return render(request, 'privacy_policy.html', context)

@login_required
def meta_auth(request):
    """ Initiates the OAuth flow to connect a Facebook Page. """
    if not settings.META_APP_ID or not settings.META_REDIRECT_URI:
         messages.error(request, _("Meta application details are not configured in settings."))
         return redirect('home')

    # Required scopes for managing pages, messages, and getting page info
    scopes = [
        'pages_show_list',          # To list pages the user manages
        'pages_manage_engagement',  # Needed for webhook management? Check docs.
        'pages_read_engagement',    # Read messages, posts, comments
        'pages_messaging',          # Send/receive FB messages
        'pages_manage_metadata',    # Subscribe page to webhooks
        # Add Instagram scopes if needed and app approved
        # 'instagram_basic',
        # 'instagram_manage_messages',
    ]

    params = {
        'client_id': settings.META_APP_ID,
        'redirect_uri': settings.META_REDIRECT_URI,
        'scope': ','.join(scopes),
        'response_type': 'code',
        # 'state': 'your_csrf_state' # Implement CSRF state protection
    }
    oauth_url = 'https://www.facebook.com/v19.0/dialog/oauth?' + urllib.parse.urlencode(params)
    return redirect(oauth_url)

# --- Meta API Helper Functions (Modified) ---

def get_manageable_pages(user_access_token):
    """ Gets a list of pages (id, name, access_token) the user can manage. """
    url = 'https://graph.facebook.com/v19.0/me/accounts'
    # Request fields needed: id, name, and the page's own access_token
    params = {'access_token': user_access_token, 'fields': 'id,name,access_token'}
    pages = []
    try:
        response = requests.get(url, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
        if data and data.get('data'):
            for page_data in data['data']:
                # Ensure we have the necessary info
                if page_data.get('id') and page_data.get('access_token'):
                    pages.append({
                        'id': page_data['id'],
                        'name': page_data.get('name', f"Page ID: {page_data['id']}"), # Use name or ID
                        'access_token': page_data['access_token']
                    })
            print(f"Found {len(pages)} manageable pages for user token.")
        else:
            print("No pages found for this user token or insufficient permissions.")
    except requests.RequestException as e:
        print(f"Error fetching page list: {e}")
        # Handle potential errors like token expiration or permission issues
        if e.response is not None:
             try:
                 error_detail = e.response.json().get('error', {}).get('message', str(e))
                 print(f"Meta API Error Detail: {error_detail}")
             except json.JSONDecodeError:
                 print(f"Meta API Error Response: {e.response.text[:200]}")
    except (KeyError, IndexError) as e:
        print(f"Error parsing page list response: {e}")

    return pages


# Removed get_first_page_id and get_page_access_token as get_manageable_pages now gets token


def subscribe_page_to_webhook(page_id, page_access_token):
    """ Subscribes the page to relevant webhook fields. """
    url = f'https://graph.facebook.com/v19.0/{page_id}/subscribed_apps'
    params = {
        'access_token': page_access_token,
        # Subscribe to message events. Add others if needed (e.g., feed, mentions).
        'subscribed_fields': 'messages,messaging_postbacks'
    }
    try:
        print(f"Attempting to subscribe Page {page_id} to webhook fields: {params['subscribed_fields']}")
        response = requests.post(url, params=params, timeout=10)
        # Check specifically for permission errors which are common
        if response.status_code == 403:
             error_data = response.json().get('error', {})
             print(f"Permission Error subscribing page {page_id}: {error_data.get('message')}")
             return {'success': False, 'error': f"Permission denied: {error_data.get('message')}"}
        response.raise_for_status() # Raise for other HTTP errors
        result = response.json()
        print(f"Webhook subscription result for {page_id}: {result}")
        # Check Meta API's success indicator
        if result.get('success'):
             return {'success': True}
        else:
             # Try to get error details if success is not true
             error_msg = result.get('error', {}).get('message', 'Unknown reason')
             print(f"Subscription failed for {page_id}: {error_msg}")
             return {'success': False, 'error': f"Subscription failed: {error_msg}"}
    except requests.RequestException as e:
        error_msg = str(e)
        if e.response is not None:
             try:
                 error_msg = e.response.json().get('error', {}).get('message', str(e))
             except json.JSONDecodeError:
                 error_msg = e.response.text[:200]
        print(f"Error subscribing page {page_id} to webhook: {error_msg}")
        return {'success': False, 'error': error_msg}
    except Exception as e:
         print(f"Unexpected error during subscription for {page_id}: {e}")
         return {'success': False, 'error': str(e)}


@login_required
def meta_callback(request):
    """ Handles the callback from Facebook, gets pages, and connects the FIRST one. """
    code = request.GET.get('code')

    if 'error' in request.GET:
        messages.error(request, _("Error during Meta authentication: {}").format(request.GET.get('error_description', 'Unknown error.')))
        return redirect('home')
    if not code:
        messages.error(request, _("Authorization code not found in callback."))
        return redirect('home')
    if not isinstance(request.user, CustomUser):
        messages.error(request, _("Invalid user type for Meta connection."))
        return redirect('home')

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
        response.raise_for_status()
        token_data = response.json()
        user_access_token = token_data.get('access_token')

        if not user_access_token:
            messages.error(request, _("Failed to retrieve access token from Meta."))
            return redirect('home')

        # Optional: Store the user token if needed for later use (e.g., refresh)
        # request.user.meta_access_token = user_access_token
        # request.user.save()

        # --- Get Manageable Pages ---
        manageable_pages = get_manageable_pages(user_access_token)
        if not manageable_pages:
             messages.error(request, _("Could not find any Facebook Pages you manage or permission denied. Please ensure you granted 'pages_show_list' permission."))
             return redirect('home')

        # --- Connect the FIRST available page ---
        # TODO: Implement a page selection UI in a future step.
        first_page = manageable_pages[0]
        page_id_to_connect = first_page['id']
        page_name_to_connect = first_page['name']
        page_token_to_connect = first_page['access_token']

        # --- Check if page is already connected by ANY user ---
        existing_connection = ConnectedPage.objects.filter(page_id=page_id_to_connect).first()
        if existing_connection:
            if existing_connection.user == request.user:
                # Already connected by this user, maybe just update token?
                existing_connection.page_access_token = page_token_to_connect
                existing_connection.page_name = page_name_to_connect # Update name too
                existing_connection.save(update_fields=['page_access_token', 'page_name', 'last_updated'])
                messages.info(request, _("Refreshed connection for page: {}").format(page_name_to_connect))
            else:
                # Connected by someone else - this is an error
                messages.error(request, _("Page '{}' (ID: {}) is already connected by another user ({}).").format(page_name_to_connect, page_id_to_connect, existing_connection.user.username))
            return redirect('connected_pages_list') # Redirect to list

        # --- Subscribe Page to Webhook ---
        subscription_result = subscribe_page_to_webhook(page_id_to_connect, page_token_to_connect)
        if not subscription_result or not subscription_result.get('success'):
             messages.warning(request, _("Failed to subscribe page '{}' to webhooks. AI responses may not work. Error: {}").format(page_name_to_connect, subscription_result.get('error', _('Unknown'))))
             # Decide if you want to proceed without subscription or stop here. Let's proceed with warning.

        # --- Create the ConnectedPage record ---
        try:
            with transaction.atomic(): # Ensure creation is atomic
                new_page = ConnectedPage.objects.create(
                    user=request.user,
                    page_id=page_id_to_connect,
                    page_name=page_name_to_connect,
                    page_access_token=page_token_to_connect,
                    is_active=True # Start as active
                    # system_prompt can be left blank initially
                )
            messages.success(request, _("Successfully connected page: {}").format(new_page.page_name))

        except Exception as e:
             # Catch potential unique constraint errors or other DB issues
             logger.error(f"Error creating ConnectedPage for {page_id_to_connect}: {e}", exc_info=True)
             messages.error(request, _("An error occurred while saving the page connection. Please try again."))
             return redirect('home')

    except requests.Timeout:
        messages.error(request, _('Request to Facebook timed out. Please try again.'))
    except requests.RequestException as e:
        error_detail = str(e)
        if e.response is not None:
            try:
                error_detail = e.response.json().get('error', {}).get('message', str(e))
            except json.JSONDecodeError:
                error_detail = e.response.text[:200]
        messages.error(request, _('Error communicating with Facebook: {}').format(error_detail))
    except Exception as e:
        logger.error(f"Unexpected error during Meta callback: {e}", exc_info=True)
        messages.error(request, _('An unexpected error occurred during Meta connection: {}').format(str(e)))

    # Redirect to the list of connected pages after success or failure
    return redirect('connected_pages_list')


def unsubscribe_page_from_webhook(page_id, page_access_token):
    """ Unsubscribes the page from webhook notifications. """
    url = f'https://graph.facebook.com/v19.0/{page_id}/subscribed_apps'
    params = {'access_token': page_access_token}
    try:
        print(f"Attempting to unsubscribe Page {page_id} from webhooks")
        response = requests.delete(url, params=params, timeout=10)
        # Don't raise for status immediately, check the JSON response first
        result = response.json()
        print(f"Webhook unsubscription result for {page_id}: {result}")
        if response.status_code == 200 and result.get('success'):
            return True
        else:
            error_msg = result.get('error', {}).get('message', f"Status: {response.status_code}")
            print(f"Failed unsubscribing {page_id}: {error_msg}")
            return False
    except requests.RequestException as e:
        error_msg = str(e)
        if e.response is not None:
            try: error_msg = e.response.json().get('error', {}).get('message', str(e))
            except json.JSONDecodeError: error_msg = e.response.text[:200]
        print(f"Error unsubscribing page {page_id} from webhooks: {error_msg}")
        return False
    except Exception as e:
         print(f"Unexpected error during unsubscription for {page_id}: {e}")
         return False

@login_required
@require_POST # Use POST for disconnect action
def disconnect_page(request, connected_page_pk):
    """ Disconnects a specific Facebook Page for the user. """
    page_to_disconnect = get_object_or_404(
        ConnectedPage,
        pk=connected_page_pk,
        user=request.user # Ensure user owns this page connection
    )
    page_name = page_to_disconnect.page_name or page_to_disconnect.page_id
    page_id = page_to_disconnect.page_id
    page_access_token = page_to_disconnect.page_access_token

    # Attempt to unsubscribe first (best effort)
    unsubscribe_success = unsubscribe_page_from_webhook(page_id, page_access_token)

    # Delete the page connection record
    try:
        page_to_disconnect.delete()
        if unsubscribe_success:
            messages.success(request, _("Successfully disconnected page '{}'.").format(page_name))
        else:
            messages.warning(request, _("Disconnected page '{}', but failed to unsubscribe from webhooks. You may need to check Meta Developer Settings.").format(page_name))
    except Exception as e:
        logger.error(f"Error deleting ConnectedPage {connected_page_pk} for user {request.user.id}: {e}", exc_info=True)
        messages.error(request, _("Failed to disconnect page '{}' due to a database error.").format(page_name))

    return redirect('connected_pages_list') # Redirect back to the list

# --- Webhook Handler (Modified) ---

@csrf_exempt
def messenger_webhook(request):
    """ Handles incoming webhook events from Meta. """

    # Verification Request (GET)
    if request.method == 'GET':
        verify_token = settings.META_VERIFY_TOKEN # Use setting
        # verify_token = 'demuraaa' # Or hardcoded for testing ONLY
        hub_mode = request.GET.get('hub.mode')
        hub_verify_token = request.GET.get('hub.verify_token')
        hub_challenge = request.GET.get('hub.challenge')

        if hub_mode == 'subscribe' and hub_verify_token == verify_token:
            print("Webhook verification successful!")
            return HttpResponse(hub_challenge, status=200)
        else:
            print(f"Webhook verification failed. Mode: {hub_mode}, Received Token: '{hub_verify_token}', Expected: '{verify_token}'")
            return HttpResponseForbidden('Invalid verification token')

    # Event Notification (POST)
    elif request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            # Log the raw incoming data for debugging if needed (be mindful of sensitive info)
            # logger.debug(f"Webhook POST data: {json.dumps(data)}")
        except json.JSONDecodeError:
            logger.error("Webhook Error: Invalid JSON received")
            return HttpResponseBadRequest("Invalid JSON")

        if data.get("object") == "page": # Facebook Pages
            for entry in data.get("entry", []):
                page_id = entry.get("id") # The Page ID the event is for
                timestamp = entry.get("time") # Timestamp of the event

                # Process messaging events
                for event in entry.get("messaging", []):
                    sender_id = event.get("sender", {}).get("id") # Person messaging page (PSID)
                    recipient_id = event.get("recipient", {}).get("id") # Page ID (should match page_id)

                    if not sender_id or not recipient_id:
                        logger.warning("Webhook Skipping: Missing sender/recipient ID in event.", extra={'event_data': event})
                        continue

                    # Sanity check: Ensure the recipient ID matches the entry's page ID
                    if str(page_id) != str(recipient_id):
                         logger.warning(f"Webhook Mismatch: Entry Page ID ({page_id}) != Recipient ID ({recipient_id}). Processing based on recipient_id.", extra={'event_data': event})
                         # Use recipient_id as the definitive page ID for lookup

                    # --- Find the ConnectedPage associated with the recipient_id ---
                    try:
                        # Use select_related to fetch user efficiently
                        connected_page = ConnectedPage.objects.select_related('user').get(
                            page_id=recipient_id,
                            is_active=True # Only process for active pages
                        )
                        custom_user = connected_page.user # Get the user who owns this page
                    except ConnectedPage.DoesNotExist:
                        # This page isn't managed by our system or is inactive
                        logger.info(f"Webhook Ignore: No active ConnectedPage found for page_id {recipient_id}.")
                        continue # Stop processing for this event

                    # Optional: Check payment status of the user
                    # if not custom_user.is_paid:
                    #     logger.info(f"Webhook Ignore: User {custom_user.username} (Page ID: {recipient_id}) is not paid.")
                    #     continue

                    # --- Process the actual message ---
                    if "message" in event:
                        message_data = event["message"]
                        message_id = message_data.get("mid")

                        # Skip echoes (messages sent BY the page itself)
                        if message_data.get("is_echo", False):
                            logger.debug(f"Webhook Skipping echo message {message_id} for page {recipient_id}.")
                            continue

                        message_text = message_data.get("text")
                        if message_text:
                            logger.info(f"Webhook Received: From PSID {sender_id} to Page {recipient_id} (User: {custom_user.username}, Page: {connected_page.page_name}): '{message_text[:100]}...'")
                            try:
                                # Pass the ConnectedPage object to the AI function
                                response_text = send_message_to_AI(connected_page, sender_id, message_text)
                                if response_text:
                                    # Send the AI's response back using the page's token
                                    send_facebook_message(connected_page.page_access_token, sender_id, response_text)
                                else:
                                    logger.info(f"AI function returned no response for message {message_id}.")
                            except Exception as e:
                                logger.error(f"Error processing message {message_id} or sending AI response for page {recipient_id}: {e}", exc_info=True)
                                # Avoid sending error details back to the user for security
                                # send_facebook_message(connected_page.page_access_token, sender_id, _("Sorry, an error occurred."))
                        else:
                            logger.info(f"Webhook Received non-text message {message_id} (e.g., attachment) from {sender_id} for page {recipient_id}. Skipping AI.")

                    # Handle postbacks if needed
                    elif "postback" in event:
                         payload = event["postback"].get("payload")
                         logger.info(f"Webhook Received postback from {sender_id} for page {recipient_id} with payload: {payload}")
                         # Add specific logic here if using postback buttons

        # Add handling for object == "instagram" if needed later
        # elif data.get("object") == "instagram":
        #      logger.info("Received Instagram webhook event (processing TBD).")

        # Always return 'OK' response to Meta quickly
        return HttpResponse("EVENT_RECEIVED", status=200)

    else:
        logger.warning(f"Webhook received unsupported method: {request.method}")
        return HttpResponseForbidden("Method not allowed")


# --- Facebook Message Sending Helper (No changes needed) ---
def send_facebook_message(page_access_token, recipient_psid, message_text):
    """ Sends a text message back to a user via the Messenger Send API. """
    if not page_access_token:
         logger.error(f"Cannot send message to {recipient_psid}: page_access_token is missing.")
         return None
    url = f'https://graph.facebook.com/v19.0/me/messages'
    headers = {'Content-Type': 'application/json'}
    params = {'access_token': page_access_token}
    payload = {
        "recipient": {"id": recipient_psid},
        "message": {"text": message_text},
        "messaging_type": "RESPONSE"
    }
    logger.info(f"Sending FB Message API Call to PSID {recipient_psid}: '{message_text[:100]}...'")
    try:
        response = requests.post(url, params=params, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        result = response.json()
        logger.info(f"FB Message Sent Successfully to {recipient_psid}. Response: {result}")
        return result
    except requests.Timeout:
        logger.error(f"Error sending FB message to {recipient_psid}: Request timed out")
        return None
    except requests.RequestException as e:
        error_msg = str(e)
        status_code = e.response.status_code if e.response is not None else 'N/A'
        if e.response is not None:
             try:
                 error_data = e.response.json().get('error', {})
                 error_msg = f"Code {error_data.get('code')}: {error_data.get('message')} (Subcode: {error_data.get('error_subcode')})"
             except json.JSONDecodeError:
                 error_msg = e.response.text[:200]
        logger.error(f"Error sending FB message to {recipient_psid}: Status {status_code}, Error: {error_msg}", exc_info=True)
        return None
    except Exception as e:
         logger.error(f"Unexpected exception sending FB message to {recipient_psid}: {str(e)}", exc_info=True)
         return None


# --- AI Interaction Logic (Modified) ---

def send_message_to_AI(connected_page, sender_id, message):
    """
    Manages conversation history and interacts with the AI model,
    using the specific page's system prompt.
    """
    if not isinstance(connected_page, ConnectedPage):
        logger.error("send_message_to_AI called with invalid connected_page object")
        return _("Internal configuration error.")

    custom_user = connected_page.user # Get the owner
    page_name = connected_page.page_name or connected_page.page_id

    try:
        # Find or create the conversation record linked to the ConnectedPage
        conversation_obj, created = conversation.objects.get_or_create(
            connected_page=connected_page,
            sender_id=sender_id,
            defaults={'messages': []} # Initialize messages
        )
        # If not created, ensure the timestamp is updated
        if not created:
            conversation_obj.last_updated = timezone.now()
            # No need to save yet, will save after adding messages

    except Exception as e:
        logger.error(f"DB Error: Failed get/create conversation for Page {connected_page.id}, sender {sender_id}: {e}", exc_info=True)
        return _("Sorry, I encountered an internal error managing our conversation history.")

    # Retrieve current message history
    # Ensure it's a list, provide default if not
    current_messages = conversation_obj.messages if isinstance(conversation_obj.messages, list) else []

    # --- Apply Page-Specific System Prompt ---
    # Use the prompt from the ConnectedPage, or a default
    system_content = connected_page.system_prompt or _("You are a helpful assistant.")
    system_message = {'role': 'system', 'content': system_content}

    # Ensure system prompt is the first message and up-to-date
    if not current_messages or current_messages[0].get('role') != 'system':
        logger.info(f"Prepending system prompt for page {page_name}, sender {sender_id}.")
        current_messages.insert(0, system_message)
    elif current_messages[0].get('content') != system_content:
        logger.info(f"Updating system prompt for page {page_name}, sender {sender_id}.")
        current_messages[0] = system_message

    # Append the latest user message with timestamp
    user_message = {
        'role': 'user',
        'content': message,
        'timestamp': timezone.now().isoformat() # Add timestamp
    }
    current_messages.append(user_message)




    # --- Call Grok/OpenAI API ---
    try:
   

        client = OpenAI(
            api_key=settings.GROK_API_KEY,
            base_url="https://api.x.ai/v1" # Ensure this is correct
            # timeout=25.0 # Increase timeout slightly?
        )

        logger.info(f"Sending {len(current_messages)} messages to Grok API for page {page_name}, sender {sender_id}.")

        # Filter out custom keys ('timestamp', 'manual') before sending to API
        api_messages = [
            {k: v for k, v in msg.items() if k in ['role', 'content']}
            for msg in current_messages
        ]


        completion = client.chat.completions.create(
            model="grok-2-latest", # Ensure model name is valid
            messages=api_messages,
            # max_tokens=1024,
            # temperature=0.7,
        )

        assistant_response_text = completion.choices[0].message.content
        logger.info(f"Grok API Response received for page {page_name}, sender {sender_id}.")

    except AuthenticationError:
         logger.critical(f"CRITICAL ERROR: Grok API Authentication Failed. Check API Key.")
         return _("AI Service connection issue (Authentication).")
    except RateLimitError:
         logger.warning(f"Grok API Rate Limit Exceeded for user {custom_user.username}.")
         return _("The AI service is currently busy, please try again in a moment.")
    except APITimeoutError:
        logger.warning(f"Grok API request timed out for page {page_name}, sender {sender_id}.")
        return _("The AI service took too long to respond, please try again.")
    except APIError as e:
        logger.error(f"Grok API Error for page {page_name}, sender {sender_id}: Status={e.status_code}, Body={e.body}", exc_info=True)
        # Avoid showing detailed API errors to the end-user
        return _("Sorry, there was an error communicating with the AI service.")
    except Exception as e:
        logger.error(f"Unexpected Error during AI API call for page {page_name}, sender {sender_id}: {e}", exc_info=True)
        return _("Sorry, an unexpected error occurred while getting the AI response.")

    # --- Save conversation and return response ---
    if assistant_response_text:
        assistant_message = {
            'role': 'assistant',
            'content': assistant_response_text,
            'timestamp': timezone.now().isoformat() # Add timestamp
        }
        current_messages.append(assistant_message)
        conversation_obj.messages = current_messages # Assign updated list
        try:
            # Save the conversation object (updates messages and last_updated)
            conversation_obj.save()
        except Exception as e:
             logger.error(f"DB Error: Failed saving conversation for Page {connected_page.id}, sender {sender_id}: {e}", exc_info=True)
             # Still return the response, but log the save failure

    return assistant_response_text


# --- AI Configuration and Testing Views (Modified) ---

# Remove the old view for user-level prompt
# @login_required
# def update_system_prompt(request): ...

# --- NEW View: List Connected Pages ---
@login_required
@require_GET # This view only displays data
def connected_pages_list(request):
    """ Displays a list of pages connected by the logged-in user. """
    pages = ConnectedPage.objects.filter(user=request.user).order_by('page_name')
    context = {
        'connected_pages': pages,
    }
    return render(request, 'connected_pages_list.html', context)

# --- NEW View: Configure a Specific Page ---
@login_required
def configure_page(request, connected_page_pk):
    """ Allows user to view details and update the system prompt for a specific page. """
    page = get_object_or_404(
        ConnectedPage,
        pk=connected_page_pk,
        user=request.user # Ensure ownership
    )
  
 
    if request.method == 'POST':
        # Handle the prompt update form submission
        form = PageSystemPromptForm(request.POST, instance=page)
        if form.is_valid():
            try:
                form.save()
                messages.success(request, _("System prompt for page '{}' updated successfully!").format(page.page_name))
                # Redirect back to the same page to see changes
                return redirect('configure_page', connected_page_pk=page.pk)
            except Exception as e:
                 logger.error(f"Error saving PageSystemPromptForm for page {page.pk}: {e}", exc_info=True)
                 messages.error(request, _("An error occurred while saving the prompt."))
        else:
            messages.error(request, _('Please correct the errors in the form below.'))
    else:
        # GET request: Show the form pre-filled with the page's current prompt
        form = PageSystemPromptForm(instance=page)

    context = {
        'page': page,
        'form': form,
        # Pass the current prompt directly for display (optional, form shows it too)
        'current_prompt': page.system_prompt
    }
    return render(request, 'configure_page.html', context)


@login_required
@ensure_csrf_cookie # For AJAX POST
def test_ai_conversation(request):
    """ Renders the page for users to test AI config FOR A SELECTED PAGE. """
    if not isinstance(request.user, CustomUser):
        # This check might be redundant with @login_required but good practice
        messages.error(request, _('This feature requires a user account.'))
        return redirect('home')

    # Get pages connected by the user to populate the dropdown
    connected_pages = ConnectedPage.objects.filter(user=request.user, is_active=True).order_by('page_name')

    if not connected_pages.exists():
         messages.warning(request, _("You need to connect at least one active page to test the AI."))
         return redirect('connected_pages_list') # Guide them to connect pages

    context = {
        'connected_pages': connected_pages,
        # No single system_prompt needed here anymore
    }
    return render(request, 'test_ai_conversation.html', context)


@login_required
@require_POST # Expect POST with JSON data
def send_test_message(request):
    """
    Handles AJAX POST for the AI test page. Uses the prompt of the SELECTED page.
    """
    if not isinstance(request.user, CustomUser):
        return JsonResponse({"error": "Unauthorized user type"}, status=401)

    try:
        data = json.loads(request.body.decode('utf-8'))
        message = data.get("message", "").strip()
        connected_page_pk = data.get("page_pk") # Get the selected page PK from frontend
    except json.JSONDecodeError:
         return JsonResponse({"error": _("Invalid JSON data in request body")}, status=400)
    except Exception as e:
        logger.error(f"Error parsing test message request body: {e}")
        return JsonResponse({"error": _("Error parsing request data")}, status=400)

    if not message:
        return JsonResponse({"error": _("Message cannot be empty")}, status=400)
    if not connected_page_pk:
         return JsonResponse({"error": _("Page selection is missing")}, status=400)

    # --- Get the selected ConnectedPage ---
    try:
        selected_page = get_object_or_404(
            ConnectedPage,
            pk=connected_page_pk,
            user=request.user, # Ensure user owns the page
            is_active=True      # Ensure page is active
        )
    except (Http404, ValueError):
        return JsonResponse({"error": _("Invalid or inactive page selected")}, status=404)
    except Exception as e:
        logger.error(f"Error fetching selected page {connected_page_pk} for test: {e}", exc_info=True)
        return JsonResponse({"error": _("Server error fetching page details")}, status=500)


    # Use a dedicated sender_id for testing, potentially including page pk
    test_sender_id = f"test_sender__{request.user.id}__{selected_page.pk}"

    # Call the main AI function, passing the SELECTED ConnectedPage object
    try:
        response_text = send_message_to_AI(selected_page, test_sender_id, message)
        if response_text is None: # Handle cases where AI function had internal error
             # The AI function already logged the specific error
             return JsonResponse({"error": _("AI service failed to generate a response.")}, status=500)

        return JsonResponse({"response": response_text})

    except Exception as e:
        logger.error(f"Error in send_test_message view for user {request.user.id}, page {selected_page.pk}: {e}", exc_info=True)
        return JsonResponse({"error": _("An unexpected server error occurred.")}, status=500)


# --- Conversation Management Views (Adapted for ConnectedPage) ---
@login_required
def inbox_view(request):
    """ Displays conversations grouped by page for the logged-in user. """
    # Fetch pages and prefetch related conversations for efficiency
    pages_with_convos = ConnectedPage.objects.filter(
        user=request.user
    ).prefetch_related(
        # Prefetch conversations ordered by last_updated
        db_models.Prefetch(
            'conversations',
            queryset=conversation.objects.order_by('-last_updated'),
            to_attr='recent_conversations' # Assign to a custom attribute
        )
    ).order_by('page_name')

    context = {'pages_with_convos': pages_with_convos}
    return render(request, 'inbox.html', context)


@login_required
def conversation_detail_view(request, connected_page_pk, sender_id):
    """ Displays messages for a specific conversation on a specific page. """
    # Ensure the user owns the page this conversation belongs to
    conversation_obj = get_object_or_404(
        conversation.objects.select_related('connected_page__user'), # Get related data efficiently
        connected_page__pk=connected_page_pk,
        sender_id=sender_id,
        connected_page__user=request.user # Authorization check
    )
    reply_form = ManualReplyForm()
    context = {
        'conversation': conversation_obj,
        'page': conversation_obj.connected_page, # Pass the page context
        'reply_form': reply_form
    }
    return render(request, 'conversation_detail.html', context)


@login_required
@require_POST
def send_manual_reply(request, connected_page_pk, sender_id):
    """ Handles POST request to send a manual reply for a specific conversation. """
    conversation_obj = get_object_or_404(
        conversation.objects.select_related('connected_page'), # Need page token
        connected_page__pk=connected_page_pk,
        sender_id=sender_id,
        connected_page__user=request.user # Authorization
    )
    page = conversation_obj.connected_page

    if not page.page_access_token:
        messages.error(request, _("Cannot send reply: Page token missing for '{}'.").format(page.page_name))
        return redirect('conversation_detail', connected_page_pk=page.pk, sender_id=sender_id)

    form = ManualReplyForm(request.POST)
    if form.is_valid():
        message_text = form.cleaned_data['message']
        api_result = send_facebook_message(page.page_access_token, conversation_obj.sender_id, message_text)

        if api_result:
            # Add manual message to history
            manual_msg_obj = {
                'role': 'assistant', # Still acting as the assistant role
                'content': message_text,
                'manual': True, # Flag as manual
                'timestamp': timezone.now().isoformat()
            }
            # Ensure messages is a list
            current_messages = conversation_obj.messages if isinstance(conversation_obj.messages, list) else []
            current_messages.append(manual_msg_obj)
            conversation_obj.messages = current_messages
            # Update last_updated implicitly by saving
            # conversation_obj.last_updated = timezone.now() # Or explicitly if auto_now=True isn't sufficient

            try:
                # Only update messages and rely on auto_now for last_updated
                conversation_obj.save(update_fields=['messages'])
                messages.success(request, _("Manual reply sent and recorded."))
            except Exception as e:
                 logger.error(f"Failed save manual reply to DB for convo {conversation_obj.id}: {e}", exc_info=True)
                 messages.warning(request, _("Reply sent via API, but failed to save to local history."))
        else:
            messages.error(request, _("Failed to send reply via Facebook API."))
    else:
        # Get the first error for a cleaner message
        error_msg = next(iter(form.errors.values()))[0] if form.errors else _("Invalid message content.")
        messages.error(request, error_msg)

    # Redirect back to the detail view
    return redirect('conversation_detail', connected_page_pk=page.pk, sender_id=sender_id)


@login_required
@require_POST
def delete_conversation_history(request, connected_page_pk, sender_id):
    """ Deletes a specific conversation history from the database. """
    conversation_to_delete = get_object_or_404(
        conversation.objects.select_related('connected_page'), # Get page name for logging
        connected_page__pk=connected_page_pk,
        sender_id=sender_id,
        connected_page__user=request.user # Authorization
    )
    conv_id = conversation_to_delete.id
    page_name = conversation_to_delete.connected_page.page_name

    logger.warning(f"User {request.user.email} deleting conversation history for sender {sender_id} on page '{page_name}' (Conv ID: {conv_id})")
    try:
        conversation_to_delete.delete()
        msg = _("Conversation history for sender %(sender_id)s on page '%(page_name)s' has been deleted.") % {'sender_id': sender_id, 'page_name': page_name}
        messages.success(request, msg)
        logger.info(f"Deleted conversation history (Conv ID: {conv_id}) by user {request.user.email}")
    except Exception as e:
        logger.error(f"Failed deleting conversation {conv_id}: {e}", exc_info=True)
        messages.error(request, _("Failed to delete conversation history."))

    # Redirect back to the main inbox view
    return redirect(reverse('inbox'))

# --- Language Switcher (No changes needed) ---
@require_POST
def set_language(request):
    """ Sets the language preference cookie based on form submission. """
    lang_code = request.POST.get('language')
    # Fallback to referrer or home
    default_redirect = reverse('home')
    next_url = request.POST.get('next', request.META.get('HTTP_REFERER', default_redirect))
    # Basic sanity check on next_url to prevent open redirect vulnerability
    if not next_url or '//' in next_url or ' ' in next_url:
         next_url = default_redirect

    if lang_code and translation.check_for_language(lang_code):
        response = HttpResponseRedirect(next_url)
        # Set cookie settings from Django settings if available, else use defaults
        response.set_cookie(
            settings.LANGUAGE_COOKIE_NAME, lang_code,
            max_age=settings.LANGUAGE_COOKIE_AGE,
            path=settings.LANGUAGE_COOKIE_PATH,
            domain=settings.LANGUAGE_COOKIE_DOMAIN,
            secure=settings.LANGUAGE_COOKIE_SECURE,
            httponly=settings.LANGUAGE_COOKIE_HTTPONLY,
            samesite=settings.LANGUAGE_COOKIE_SAMESITE
        )
        logger.info(f"Set language to '{lang_code}' for user {request.user.id if request.user.is_authenticated else 'anonymous'}")
        # messages.success(request, _("Language changed.")) # Optional feedback
        return response
    else:
        logger.warning(f"Attempted to set invalid language code: '{lang_code}' by user {request.user.id if request.user.is_authenticated else 'anonymous'}")
        messages.error(request, _("Invalid language selected."))
        return HttpResponseRedirect(next_url) # Redirect anyway