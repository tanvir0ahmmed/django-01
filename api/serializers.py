from django.contrib.auth.models import User
from .models import Articales
from rest_framework import serializers
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate

class ArticalesSerializer(serializers.ModelSerializer):
    owner = serializers.ReadOnlyField(source='owner.username')
    class Meta:
        model = Articales
        fields = ['id','title', 'description', 'created_at','owner', 'user']#
    
    def create(self, validated_data):
        user = Articales.objects.create(title=validated_data['title'],description=validated_data['description']
                                        ,user=validated_data['user'])
        return user
    
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password']
        
        extra_kwargs = {
            'password':{
                'write_only': True,
                'required':True,
            }
        }
    
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    
class LogInSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password']
        #''' 
        extra_kwargs = {
            'password':{
                'write_only': True,
                'required':True,
            }
        } 
        #'''