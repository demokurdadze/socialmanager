# tasks.py
from celery import shared_task
from django.core.cache import cache
from .models import MessengerUser, CombinedMessage

@shared_task
def combine_messages(sender_id):
    try:
        user = MessengerUser.objects.get(sender_id=sender_id)
        if not user.is_paid:  # Final payment check
            return
        
        cache_key = f'msg_{sender_id}'
        fragments = cache.get(cache_key, [])
        if fragments:
            combined_text = ' '.join(fragments)
            CombinedMessage.objects.create(user=user, text=combined_text)
            cache.delete(cache_key)
    except MessengerUser.DoesNotExist:
        pass  # User deleted mid-process