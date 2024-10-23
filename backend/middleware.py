from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken
from django.shortcuts import redirect
from django.contrib import messages
from django.urls import reverse

class TokenExpiryCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        access_token = request.session.get('access_token')

        if access_token:
            try:
                # Check if the token is expired
                token = AccessToken(access_token)
                token.check_exp()

            except TokenError:
                # If token is invalid or expired, log out
                if request.path != reverse('login'):
                        messages.error(request, 'Your session has expired. Please log in again.')

                # Prevent redirection loop by checking if already on the login page
                if request.path != reverse('login'):
                    return redirect('login')  # Redirect to the login view

        # Continue processing the request if no issues
        response = self.get_response(request)
        return response