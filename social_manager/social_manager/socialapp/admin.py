# socialapp/admin.py

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
import json

# Import your models
from .models import CustomUser, ConnectedPage, conversation
# REMOVED the import for non-existent forms:
# from .forms import CustomUserCreationForm, CustomUserChangeForm

# --- Custom User Admin ---
# Updated to reflect current CustomUser fields
class CustomUserAdmin(UserAdmin):
    # REMOVED references to non-existent forms:
    # add_form = CustomUserCreationForm
    # form = CustomUserChangeForm
    model = CustomUser

    # Update list_display with current fields
    list_display = ['username', 'email', 'is_paid', 'is_staff', 'is_active', 'date_joined']
    # Add is_paid to filters if desired
    list_filter = UserAdmin.list_filter + ('is_paid',)

    # Update fieldsets to include 'is_paid' and 'meta_access_token'
    # These fieldsets correctly tell the default admin forms which fields to display.
    fieldsets = UserAdmin.fieldsets + (
        (_('Other Info'), {'fields': ('is_paid', 'meta_access_token',)}),
    )
    # Update add_fieldsets similarly
    add_fieldsets = UserAdmin.add_fieldsets + (
         (_('Other Info'), {'fields': ('is_paid', 'meta_access_token',)}), # Match the fields in CustomUser
    )

# --- Connected Page Admin ---
@admin.register(ConnectedPage)
class ConnectedPageAdmin(admin.ModelAdmin):
    list_display = ('page_name', 'page_id', 'user_link', 'is_active', 'connected_at', 'has_system_prompt')
    list_filter = ('is_active', 'user')
    search_fields = ('page_name', 'page_id', 'user__username', 'user__email')
    readonly_fields = ('user', 'page_id', 'page_name', 'page_access_token_display', 'connected_at', 'last_updated')
    fields = (
        'user',
        ('page_name', 'page_id'),
        'is_active',
        'system_prompt',
        'page_access_token_display',
        ('connected_at', 'last_updated')
    )

    @admin.display(description=_('User'))
    def user_link(self, obj):
        from django.urls import reverse
        link = reverse(f"admin:{obj.user._meta.app_label}_{obj.user._meta.model_name}_change", args=[obj.user.pk])
        return format_html('<a href="{}">{}</a>', link, obj.user.username)

    @admin.display(description=_('Has Prompt?'), boolean=True)
    def has_system_prompt(self, obj):
        return bool(obj.system_prompt)

    @admin.display(description=_('Page Access Token'))
    def page_access_token_display(self, obj):
        if obj.page_access_token:
            token_len = len(obj.page_access_token)
            if token_len > 15:
                 return f"{obj.page_access_token[:5]}...{obj.page_access_token[-5:]} ({_('hidden')})"
            else:
                 return f"{_('Token present')} ({_('hidden')})"
        return _("Not Set")

# --- Conversation Admin ---
@admin.register(conversation)
class ConversationAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'connected_page_link', 'sender_id', 'message_count', 'last_updated')
    list_filter = ('connected_page__user', 'connected_page')
    search_fields = ('sender_id', 'connected_page__page_name', 'connected_page__page_id', 'connected_page__user__username')
    readonly_fields = ('connected_page', 'sender_id', 'messages_display', 'last_updated')
    fields = ('connected_page', 'sender_id', 'last_updated', 'messages_display')

    @admin.display(description=_('Connected Page'))
    def connected_page_link(self, obj):
        from django.urls import reverse
        link = reverse(f"admin:{obj.connected_page._meta.app_label}_{obj.connected_page._meta.model_name}_change", args=[obj.connected_page.pk])
        return format_html('<a href="{}">{}</a>', link, obj.connected_page.page_name or obj.connected_page.page_id)

    @admin.display(description=_('Message Count'))
    def message_count(self, obj):
        if isinstance(obj.messages, list):
            count = len(obj.messages)
            if count > 0 and obj.messages[0].get('role') == 'system':
                 return count - 1
            return count
        return 0

    @admin.display(description=_('Messages'))
    def messages_display(self, obj):
        try:
            pretty_json = json.dumps(obj.messages, indent=2, ensure_ascii=False)
            return format_html("<pre style='white-space: pre-wrap; word-break: break-all; max-height: 500px; overflow-y: auto; border: 1px solid #ccc; padding: 5px; background: #f9f9f9;'>{}</pre>", pretty_json)
        except Exception:
            return str(obj.messages) # Fallback

# --- Register CustomUser ---
# Register CustomUser with the updated CustomUserAdmin
admin.site.register(CustomUser, CustomUserAdmin)

# The @admin.register decorator handles registration for ConnectedPage and conversation.