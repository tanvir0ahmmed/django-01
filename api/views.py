from rest_framework.views import APIView
from .models import Articales
from django.contrib.auth.models import User
from .serializers import ArticalesSerializer, UserSerializer, LogInSerializer
from django.shortcuts import render
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework import status, generics, response
from rest_framework.authtoken.models import Token
# Create your views here.
from rest_framework import permissions, viewsets
from rest_framework.response import Response
from django.contrib.auth import authenticate  # , login, logout

#from django.core.exceptions import ObjectDoesNotExist

from django.http import QueryDict
from django.http import Http404
#from django.contrib.auth.decorators import login_required
#from rest_framework.decorators import action
#from django.http import HttpResponse, HttpResponseRedirect

""" import os
import requests
import jwt
import hashlib """
from urllib.parse import urlencode

""" import random
import string """

""" 
class Callback(APIView):
    print('Callback')

    def get(self, request):
        print('H e l l o')
        # print(request.GET.get('code'))
        if request.GET.get('state') != request.session.get('googleauth_csrf'):
            return HttpResponse('Invalid state parameter', status=401)
        data = {
            #'code': request.GET.get('code'),
            #'code': request.data.get('code'),
            'code': request.headers.get('Authorization'),
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'redirect_uri': CALLBACK_DOMAIN,
            'grant_type': 'authorization_code',
        }
        print('H e l l o 1', data['code'])
        resp = requests.post(GOOGLE_TOKEN_ENDPOINT, data=data)
        print('H e l l o 2', resp)
        if resp.status_code != 200:
            return HttpResponse('Invalid token response', status=401)

        tokens = resp.json()
        id_token = jwt.decode(tokens['id_token'], verify=False)
        dt = {
            'tokens': tokens,
            'id_token': id_token,
        }
        # print('>>>>>>>>>>>>',id_token,'\n)))))))))))))',tokens)
        if (not id_token['email_verified']
            or id_token['iss'] != 'https://accounts.google.com'
                or id_token['aud'] != CLIENT_ID):
            return HttpResponse('Forged response', status=401)
        attributes = {
            'email': id_token.get('email'),
            'access_token': tokens['access_token'],
        }
        # print('---------------',attributes)
        #print('>>>>>>>', id_token['name'])
        user = User.objects.filter(email=attributes['email'])
        # print(email,type(email))
        data = {}
        if not user:
            letters = string.ascii_lowercase
            username = ''.join(random.choice(letters) for i in range(10))
            #password = ''.join(random.choice(letters) for i in range(15))
            password = CLIENT_SECRET
            provider = 'google'
            data = {'username': username, 'password': password,
                    'email': attributes['email']}
            resp = requests.post('http://127.0.0.1:8000/users/', data=data)
            resp = resp.json()
            data = {'username': resp['username'], 'password': resp['password']}
            #resp = requests.post('http://127.0.0.1:8000/login/', data=data)
            # print('Response------------->',resp.json())
            #user = User.objects.get(username=resp['username'])
            #print('User: ',user)
            #token = Token.objects.create(user=user)
            #print('token created ',token)
        else:
            #user = User.objects.filter(email=attributes['email'])
            #myDict = dict(user.iterlists())
            li = list(user.values('username'))
            li = li[0]
            print('User-----', user.values('username'), li['username'])
            user = User.objects.filter(email=attributes['email'])
            data = {'username': li['username'], 'password': CLIENT_SECRET}
            requests.post('http://127.0.0.1:8000/login/', data=data)
            # print(resp.json())
        return Response(dt)
 """

class CheckUser(APIView):
    def post(self, request):
        user = User.objects.filter(email=request.data.get('email'))
        if not user:
            status='new'
        else:
            status='old'
        return Response({'status':status})

class ArticlesView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = (TokenAuthentication,)

    def get_data(self, key, request):
        user_id = Token.objects.get(key=key).user_id
        title = request.data.get('title')
        description = request.data.get('description')
        data = {'title': title, 'description': description, 'user': user_id}
        query_dict = QueryDict('', mutable=True)
        query_dict.update(data)
        return query_dict

    def get_object(self, pk):
        try:
            return Articales.objects.get(pk=pk)
        except Articales.DoesNotExist:
            raise Http404

    def get(self, request):
        user_id = Token.objects.get(key=self.request.auth.key).user_id
        article = Articales.objects.filter(user=user_id)
        serializer = ArticalesSerializer(article, many=True)
        return Response(serializer.data)

    def post(self, request):
        data = self.get_data(self.request.auth.key, request)
        serializer = ArticalesSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        data = self.get_data(self.request.auth.key, request)
        article = self.get_object(pk=pk)
        serializer = ArticalesSerializer(article, data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        article = self.get_object(pk)
        article.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserViewSet(viewsets.ModelViewSet):
    authentication_classes = (TokenAuthentication,)
    queryset = User.objects.all()
    serializer_class = UserSerializer


class LogInViewSet(APIView):
    authentication_classes = (TokenAuthentication,)

    def post(self, request, format=None):
        user = authenticate(username=request.data.get('username'),
                            password=request.data.get('password'))
        if user:
            token = Token.objects.create(user=user)
            return Response({'username': user.username, 'id': user.id, 'token': token.key}, status=status.HTTP_201_CREATED)

        return Response({'error': 'username or password is not match'}, status=status.HTTP_400_BAD_REQUEST)


class LogOutViewSet(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = (TokenAuthentication,)

    def get(self, request):
        request.user.auth_token.delete()
        return Response({'massege': 'successfully logout'}, status=status.HTTP_200_OK)


# garbage code
""" 
class ArticlesViewSet(viewsets.ModelViewSet):
     
    ''' def get_queryset(self):
       access_token = self.request.META.get('TOKEN')
   user_from_token = find_user_given_token(access_token)
   return Movie.objects.filter(owner = user_from_token) '''
    permission_classes=[IsAuthenticated]
    authentication_classes=(TokenAuthentication,)
    @action(detail=True, methods=['post'])
    def articlesPost(self,request):
        
        serializer_class = ArticalesSerializer 
        print('Request:',request)
        serializer = ArticalesSerializer(data=request.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    def get_queryset(self) :
        #user = Token.objects.get(key='token string').user
        user_id = Token.objects.get(key=self.request.auth.key).user_id
        #user = self.request.user
        print(user_id)
        return Articales.objects.filter(user=user_id)
    ''' def perform_create(self, serializers):
        print('HELLO')
        user_id = Token.objects.get(key=self.request.auth.key).user_id
        print('ID->',user_id)
        serializers.save(owner=self.request.user)
        print('--->>>>',serializers,'\n',self.request.user,self.request.auth.key,'-') 
        '''
        """


""" class ArticlesViewSet(generics.ListCreateAPIView):
    permission_classes=[IsAuthenticated]
    authentication_classes=(TokenAuthentication,)
    serializer_class = ArticalesSerializer
    
    def get_queryset(self) :
        user = self.request.user
        print(user)
        return Articales.objects.filter(user=user)
    
    serializer_class = ArticalesSerializer
    def perform_create(self, serializers):
        serializers.save(owner=self.request.user) """


''' class LogInViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = LogInSerializer
    
    def post(self, serializers):
        print('Log In',serializers) '''
