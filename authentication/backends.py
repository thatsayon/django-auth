from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

User = get_user_model()


class EmailOrUsernameBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # Ensure username is not None
        if not username:
            return None

        try:
            # Check if the username is an email or a username
            user = (
                User.objects.get(email=username)
                if '@' in username
                else User.objects.get(username=username)
            )
        except User.DoesNotExist:
            return None

        # Check password and if the user is allowed to authenticate
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None

    def user_can_authenticate(self, user):
        """
        Reject users with is_active=False. Customize if needed.
        """
        return user.is_active
