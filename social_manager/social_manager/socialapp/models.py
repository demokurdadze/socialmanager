from django.conf import settings # Use settings.AUTH_USER_MODEL
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _

# --- Updated CustomUser Model ---
class CustomUser(AbstractUser):
    """
    Extended user model. Page-specific details are now in ConnectedPage.
    """
    is_paid = models.BooleanField(default=False)
    # Keep meta_access_token if you plan to use it for token refresh or other user-level Meta API calls
    meta_access_token = models.CharField(
        max_length=512, # Tokens can be long
        blank=True,
        null=True,
        help_text=_("Stores the user-level Meta access token (long-lived if possible).")
    )
    # page_id, page_access_token, system_prompt are REMOVED from here.
    email = models.EmailField(unique=True) # Ensure email is unique as per allauth standard

    def __str__(self):
        return self.username

# --- NEW ConnectedPage Model ---
class ConnectedPage(models.Model):
    """
    Represents a Facebook/Instagram Page connected by a user.
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, # Best practice
        on_delete=models.CASCADE,
        related_name='connected_pages'
    )
    page_id = models.CharField(
        _("Page ID"),
        max_length=255,
        unique=True, # A page can only be connected once across the system
        help_text=_("The unique Facebook or Instagram Page ID.")
    )
    page_name = models.CharField(
        _("Page Name"),
        max_length=255,
        blank=True, # Might not always be available initially
        null=True,
        help_text=_("The name of the Facebook or Instagram Page.")
    )
    page_access_token = models.CharField(
        _("Page Access Token"),
        max_length=512, # Tokens can be long
        help_text=_("The access token specific to this page.")
    )
    # The system prompt is now specific to this page
    system_prompt = models.TextField(
        _("Page-Specific AI System Prompt"),
        blank=True,
        null=True,
        help_text=_("AI instructions for interacting via this page. Leave blank to use a default.")
    )
    connected_at = models.DateTimeField(_("Connected At"), auto_now_add=True)
    last_updated = models.DateTimeField(_("Last Updated"), auto_now=True)
    is_active = models.BooleanField(
        _("Is Active"),
        default=True,
        help_text=_("Webhook events will only be processed for active pages.")
    )
    # Optional: Store platform type if needed (e.g., 'facebook', 'instagram')
    # platform = models.CharField(max_length=20, default='facebook')

    class Meta:
        verbose_name = _("Connected Page")
        verbose_name_plural = _("Connected Pages")
        # Ensure a user doesn't accidentally connect the same page twice
        # unique_together = ('user', 'page_id') # No, page_id must be unique globally

    def __str__(self):
        return f"{self.page_name or self.page_id} ({self.user.username})"

# --- Removed MessengerUser Model ---
# This model seems redundant if conversations are linked directly to the user
# and we can derive payment status from the user. If you had specific logic
# tied to MessengerUser, you might need to adapt it.
# class MessengerUser(models.Model):
#     sender_id = models.CharField(max_length=255, unique=True)
#     is_paid = models.BooleanField(default=False)
#     last_message_time = models.DateTimeField(auto_now=True)
#     user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

# --- Removed CombinedMessage Model ---
# This model seems unused, the conversation model holds messages.
# class CombinedMessage(models.Model):
#     user = models.ForeignKey(MessengerUser, on_delete=models.CASCADE)
#     text = models.TextField()
#     timestamp = models.DateTimeField(auto_now_add=True)

# --- Updated conversation Model ---
# socialapp/models.py
# ... other models ...

class conversation(models.Model):
    """
    Stores conversation history between a Page and an end-user (sender).
    """
    # Link to the specific page the conversation is happening on
    connected_page = models.ForeignKey(
        ConnectedPage,
        on_delete=models.CASCADE,
        related_name='conversations',
        null=True  # <--- ADD THIS TEMPORARILY
    )
    # The ID of the person messaging the page (Page-Scoped ID - PSID)
    sender_id = models.CharField(
        _("Sender ID (PSID)"),
        max_length=255 # PSIDs can be long
    )
    # Store messages as JSON (role, content, timestamp)
    messages = models.JSONField(default=list)
    # Timestamp of the last message received/sent in this conversation
    last_updated = models.DateTimeField(_("Last Updated"), auto_now=True)

    class Meta:
        verbose_name = _("Conversation")
        verbose_name_plural = _("Conversations")
        unique_together = ('connected_page', 'sender_id')
        ordering = ['-last_updated']

    def __str__(self):
         # Handle case where connected_page might be None temporarily
        page_name = self.connected_page.page_name if self.connected_page else "UNKNOWN PAGE"
        page_id = self.connected_page.page_id if self.connected_page else "UNKNOWN ID"
        return f"Chat with {self.sender_id} on {page_name or page_id}"


    def get_last_message_text(self):
        # ... (no change needed here) ...
        if isinstance(self.messages, list) and self.messages:
            last_msg = self.messages[-1]
            return last_msg.get('content', '')[:100] # Truncate for preview
        return ""

    @property
    def sender_name(self):
        # ... (no change needed here) ...
        return self.sender_id