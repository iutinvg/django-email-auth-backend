""" Authentication backend. Please use slugify function to get username from email """

from django.contrib.auth.models import User
from django.contrib.auth.backends import ModelBackend

from tastypie.authentication import ApiKeyAuthentication


class EmailAuthBackend(ModelBackend):
    """
    Email Authentication Backend

    Allows a user to sign in using an email/password pair rather than
    a username/password pair.
    """

    def authenticate(self, username=None, password=None):
        """ Authenticate a user based on email address as the user name. """
        try:
            user = User.objects.get(email=username)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

    def supports_inactive_user(self):
        return False


class EmailApiKeyAuthentication (ApiKeyAuthentication):
    """ The same as base class, but use email to find user """

    def is_authenticated(self, request, **kwargs):
        email = request.GET.get('username') or request.POST.get('username')
        api_key = request.GET.get('api_key') or request.POST.get('api_key')

        if not email or not api_key:
            return self._unauthorized()

        try:
            user = User.objects.get(email=email)
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            return self._unauthorized()

        request.user = user
        return self.get_key(user, api_key)
