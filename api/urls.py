from django.contrib import admin
from django.urls import path,include
from rest_framework.routers import DefaultRouter
from api import views
from rest_framework.authtoken.views import obtain_auth_token

router = DefaultRouter()
#router.register(r'articles2',views.ArticlesViewSet,basename='articles')
router.register(r'users', views.UserViewSet)
#router.register(r'login', views.LogInViewSet)
urlpatterns = [
    path('', include(router.urls)),
    path('auth/', obtain_auth_token),
    path('login/',views.LogInViewSet.as_view()),
    path('logout/',views.LogOutViewSet.as_view()),
    path('articles/',views.ArticlesView.as_view()),
    path('articles/<int:pk>/',views.ArticlesView.as_view()),
    #path('articales/',views.ArticlesViewSet.as_view())
]