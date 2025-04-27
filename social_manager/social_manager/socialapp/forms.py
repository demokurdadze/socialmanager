from django import forms
from django.utils.translation import gettext_lazy as _
from .models import ConnectedPage # Import the new model

# --- Manual Reply Form (Keep as is) ---
class ManualReplyForm(forms.Form):
    message = forms.CharField(
        widget=forms.Textarea(attrs={
            'rows': 2,
            'placeholder': _('Type your manual reply...'),
            'class': 'form-input manual-reply-textarea', # Add classes for styling/JS
            'style': 'min-height: 40px; resize: vertical;', # Basic inline style
        }),
        label="", # Hide default label, use placeholder
    )

# --- Remove SystemPromptForm for CustomUser ---
# class SystemPromptForm(forms.ModelForm):
#     class Meta:
#         model = CustomUser
#         fields = ['system_prompt']
#         # ... widgets etc ...

# --- NEW Form for ConnectedPage prompt ---
class PageSystemPromptForm(forms.ModelForm):
    """
    Form for editing the system_prompt of a specific ConnectedPage.
    """
    class Meta:
        model = ConnectedPage
        fields = ['system_prompt'] # Only edit the prompt field
        widgets = {
            'system_prompt': forms.Textarea(attrs={
                'rows': 15, # Make it reasonably tall
                'placeholder': _("Enter the AI instructions, context, and personality for this specific page. This defines how the AI will respond to messages received via this page. Leave blank to use a general default behavior."),
                'class': 'form-input font-mono text-sm', # Use consistent styling, add mono font maybe
                'style': 'min-height: 300px; resize: vertical;', # Ensure decent height
            }),
        }
        labels = {
            # Use a more generic label as the context (page name) will be shown elsewhere
            'system_prompt': _("Page AI System Prompt"),
        }
        help_texts = {
             'system_prompt': _("This prompt guides the AI's responses ONLY when interacting via THIS specific page."),
        }