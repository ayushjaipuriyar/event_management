from datetime import datetime, timedelta
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer, SignupSerializer, LoginSerializer

User = get_user_model()

class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignupSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'detail': 'User registered successfully.'}, status=status.HTTP_201_CREATED)

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        refresh = RefreshToken.for_user(user)

        user_serializer = UserSerializer(user)
        response = Response({'user': user_serializer.data, 'detail': 'User logged in successfully.'}, status=status.HTTP_200_OK)
        response.set_cookie('refresh_token', str(refresh), expires=datetime.now() + timedelta(days=7), httponly=True)
        response.set_cookie('access_token', str(refresh.access_token), expires=datetime.now() + timedelta(days=1), httponly=True)
        return response

class UserDetailView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)

