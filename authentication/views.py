from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer
)
from django.contrib.auth import get_user_model

User = get_user_model()


class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User registration successful"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            username_or_email = serializer.validated_data.get(
                "username_or_email")
            password = serializer.validated_data.get("password")

            user = authenticate(
                request, username=username_or_email, password=password)

            if user:
                return Response(
                    {
                        "message": "Login successful",
                        "user": {
                            "email": user.email,
                            "username": user.username,
                            "full_name": user.full_name,
                        },
                    },
                    status=status.HTTP_200_OK,
                )

            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
