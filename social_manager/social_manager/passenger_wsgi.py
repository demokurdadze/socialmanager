import os
import sys

# Add the project directory to the Python path
path = os.path.dirname(os.path.abspath(__file__))
if path not in sys.path:
    sys.path.append(path)

# Set the Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "social_manager.settings")

# Import the WSGI application
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()