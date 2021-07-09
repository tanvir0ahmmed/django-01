from django.db import models

# Create your models here.
from django.contrib.auth.models import User

class Articales(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, related_name='user', on_delete=models.CASCADE)
    
    class Meta:
        ordering = ('created_at',)