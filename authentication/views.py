from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.db import transaction
from rest_framework import status
from django.contrib.auth import authenticate
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer
)
from .utils import (
    generate_otp,
    verify_otp
)

User = get_user_model()


class UserRegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            with transaction.atomic():
                user = serializer.save()

                email_otp = generate_otp()
                user.email_otp = email_otp
                user.save()

                try:
                    email_subject = "Confirm your email"
                    email_body = render_to_string(
                        'confirm_email.html', {'email_otp': email_otp})
                    email = EmailMultiAlternatives(
                        email_subject, '', to=[user.email])
                    email.attach_alternative(email_body, "text/html")
                    email.send()

                except Exception as e:
                    user.delete()
                    return Response({"error": "Failed to send verification email. User registration rolled back."}, status=status.HTTP_400_BAD_REQUEST)

                return Response({"message": "User registration successful"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTP(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        email_otp = request.data.get('email_otp')

        if not email or not email_otp:
            return Response({"error": "Email and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Get the user based on email
            user = User._default_manager.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        # Validate the OTP
        if email_otp != user.email_otp:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        # Activate the user
        user.is_active = True
        user.is_email_verified = True
        user.email_otp = None
        user.save()

        # Send a welcome email
        email_subject = "Welcome to Sahityo Jogot"
        email_body = render_to_string(
            'welcome.html', {'user_name': user.full_name})
        email = EmailMultiAlternatives(email_subject, '', to=[user.email])
        email.attach_alternative(email_body, "text/html")
        email.send()

        return Response({"message": "Account activated successfully."}, status=status.HTTP_200_OK)


class UserLoginView(APIView):
    permission_classes = [AllowAny]  # Open to unauthenticated users

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            username_or_email = serializer.validated_data.get(
                "username_or_email")
            password = serializer.validated_data.get("password")

            if not username_or_email:
                return Response({"error": "Username or email is required."}, status=status.HTTP_400_BAD_REQUEST)

            # Authenticate using the custom backend
            user = authenticate(
                request, username=username_or_email, password=password)

            if user:
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                access = refresh.access_token

                return Response(
                    {
                        "tokens": {
                            "refresh": str(refresh),
                            "access": str(access),
                        },
                    },
                    status=status.HTTP_200_OK,
                )

            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
