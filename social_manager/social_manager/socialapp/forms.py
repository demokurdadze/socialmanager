from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import CustomUser
from django import forms


class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ('username', 'password')

class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = CustomUser
        fields = ('username', 'meta_access_token')
        


class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = CustomUser
        fields = ('username', 'email')  # Include your custom fields

class SystemPromptForm(forms.ModelForm):
    """
    Form for users to update their AI system prompt.
    """
    system_prompt = forms.CharField(
        widget=forms.Textarea(attrs={
            'rows': 8, # Provide more space for longer prompts
            'placeholder': 'e.g., You are a friendly and helpful assistant for "My Flower Shop". Your goal is to answer questions about flower types, availability, and delivery options. You can also take simple orders for bouquets listed on our website [link]. Ask for the recipient\'s name, address, desired delivery date, and a card message. Be polite and professional.'
        }),
        help_text="Define the base behavior, role, knowledge, and personality of your AI assistant. This guides all its responses. Leave blank to use the default system behavior.",
        required=False # Allow users to clear the prompt and use the default
    )

    class Meta:
        model = CustomUser
        fields = ['system_prompt'] # Only include this field in the form