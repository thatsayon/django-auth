from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
import re

User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'full_name', 'date_of_birth',
                  'gender')

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError(
                _("Password must be at least 8 characters long."))
        if not any(char.isupper() for char in value):
            raise serializers.ValidationError(
                _("Password must contain at least one uppercase letter."))
        if not any(char.islower() for char in value):
            raise serializers.ValidationError(
                _("Password must contain at least one lowercase letter."))
        if not any(char.isdigit() for char in value):
            raise serializers.ValidationError(
                _("Password must contain at least one digit."))
        if not re.search(r"[!@#$%^&*()_+{}\[\]:;\"'\\|<,>.?/`~-]", value):
            raise serializers.ValidationError(
                _("Password must contain at least one special character."))
        validate_password(value)
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            full_name=validated_data['full_name'],
            date_of_birth=validated_data['date_of_birth'],
            gender=validated_data['gender'],
            password=validated_data['password'],
            is_active=False
        )
        return user
