from django.urls import path
from .views import SigninView, LogoutView, SignupView, TokenRefreshView, UserInfoView, UpdateUserView


app_name = 'account'
urlpatterns = [
    # FBV url path
    path("signup/", SignupView.as_view()),
    path("signin/", SigninView.as_view()),
    path("logout/", LogoutView.as_view()),
    path('refresh/', TokenRefreshView.as_view()),
    path("info/", UserInfoView.as_view()),
    path("edit/", UpdateUserView.as_view())
]