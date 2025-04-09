

from django.contrib.auth.models import AbstractUser
from django.db import models

# class CustomUser(AbstractUser):
#     meta_access_token = models.CharField(
#         max_length=255,
#         blank=True,
#         null=True,
#         help_text="Stores the meta access token."
#     )
    
# models.py
class CustomUser(AbstractUser):
    is_paid = models.BooleanField(default=False)
    meta_access_token = models.CharField(max_length=255, blank=True, null=True)
    page_id = models.CharField(max_length=255, blank=True, null=True)  # Add this
    page_access_token = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(unique=True)
    system_prompt = models.TextField(blank=True, null=True)
    
    
class MessengerUser(models.Model):
    sender_id = models.CharField(max_length=255, unique=True)  # Facebook sender ID
    is_paid = models.BooleanField(default=False)  # Payment status
    last_message_time = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

class CombinedMessage(models.Model):
    user = models.ForeignKey(MessengerUser, on_delete=models.CASCADE)
    text = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
class conversation(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    messages = models.JSONField()
    sender_id = models.CharField(max_length=20)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

