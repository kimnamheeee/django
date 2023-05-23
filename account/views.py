# accounts/views.py
from django.contrib.auth.models import User 
from django.contrib import auth 
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

from .serializers import UserSerializer,UserProfileSerializer
from .models import UserProfile

def set_token_on_response_cookie(user:User) -> Response:
    token = RefreshToken.for_user(user)
    user_profile = UserProfile.objects.get(user=user)
    user_profile_serializer = UserProfileSerializer(user_profile)
    res = Response(user_profile_serializer.data, status=status.HTTP_200_OK)
    res.set_cookie('refresh_token', value=str(token))
    res.set_cookie('access_token', value=str(token.access_token))
    return res



class SignupView(APIView):
    def post(self, request):
        print(request.user)
        college=request.data.get('college')
        major=request.data.get('major')

        user_serialier = UserSerializer(data=request.data)
        if user_serialier.is_valid(raise_exception=True):
            user = user_serialier.save()
            
        user_profile = UserProfile.objects.create(
            user=user,
            college=college,
            major=major
        ) 
        return set_token_on_response_cookie(user)
        
class SigninView(APIView):
    def post(self, request):
        try:
            user = User.objects.get(
                username=request.data['username'],
                password=request.data['password']
            )
        except:
            return Response({"detail": "아이디 또는 비밀번호를 확인해주세요."}, status=status.HTTP_400_BAD_REQUEST)
        return set_token_on_response_cookie(user)
        
class LogoutView(APIView):
    def post(self, request):
        if not request.user.is_authenticated:
            return Response({"detail": "로그인 후 다시 시도해주세요."}, status=status.HTTP_401_UNAUTHORIZED)
        RefreshToken(request.data['refresh']).blacklist()
        return Response(status=status.HTTP_204_NO_CONTENT)      
        
class TokenRefreshView(APIView):
    def post(self, request):
        is_access_token_valid = request.user.is_authenticated
        refresh_token = request.data['refresh']
        try:
            RefreshToken(refresh_token).verify()
            is_refresh_token_blacklisted = True
        except:
            is_refresh_token_blacklisted = False
        if not is_access_token_valid :  
            if not is_refresh_token_blacklisted:
                return Response({"detail": "login 을 다시 해주세요."}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                new_access_token = str(RefreshToken(refresh_token).access_token)
        else:
            user = request.user
            token = AccessToken.for_user(user)
            new_access_token = str(token)
        response = Response({"detail": "token refreshed"}, status=status.HTTP_200_OK)
        return response.set_cookie('access_token', value=str(new_access_token))