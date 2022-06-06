from django.db import models

class Usuarios(models.Model):
    name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)