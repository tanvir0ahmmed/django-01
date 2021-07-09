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
from django.contrib.auth import authenticate #, login, logout

from django.core.exceptions import ObjectDoesNotExist

from django.http import QueryDict
from django.http import Http404
#from django.contrib.auth.decorators import login_required
#from rest_framework.decorators import action


class ArticlesView(APIView):
    permission_classes=[IsAuthenticated]
    authentication_classes=(TokenAuthentication,)
    
    def get_data(self,key,request):
        user_id = Token.objects.get(key=key).user_id
        title = request.data.get('title')
        description = request.data.get('description')
        data = {'title':title,'description':description,'user':user_id}
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
        data = self.get_data(self.request.auth.key,request)
        serializer = ArticalesSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request, pk):
        data = self.get_data(self.request.auth.key,request)
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
    authentication_classes=(TokenAuthentication,)
    queryset = User.objects.all()
    serializer_class = UserSerializer

class LogInViewSet(APIView):
    authentication_classes=(TokenAuthentication,)
    def post(self, request, format=None):
        user = authenticate(username=request.data.get('username'),
                                password=request.data.get('password'))
        if user:
            token = Token.objects.create(user=user)
            return Response({'username':user.username, 'id':user.id, 'token':token.key}, status=status.HTTP_201_CREATED)
        
        return Response({'error':'username or password is not match'}, status=status.HTTP_400_BAD_REQUEST)
    
class LogOutViewSet(APIView):
    permission_classes=[IsAuthenticated]
    authentication_classes=(TokenAuthentication,)
    def get(self, request):
        request.user.auth_token.delete()
        return Response({'massege':'successfully logout'},status=status.HTTP_200_OK)
    
    

#garbage code

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
