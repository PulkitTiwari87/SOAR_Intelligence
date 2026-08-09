import requests
import json
import uuid
import time
import random

DASHBOARD_URL = "http://localhost:3000/api/incidents"
# Note: You would normally need a valid JWT token, but let's assume we can inject via MongoDB if API needs auth.

# Actually, it's easier to inject directly into MongoDB for the demo if Auth is enabled on the route.
