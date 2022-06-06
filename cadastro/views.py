from django.shortcuts import render, redirect
from django.contrib import messages, auth
from django.core.validators import validate_email
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required

def register(request):
    if request.method != 'POST':
        return render(request, 'cadastro/register.html')

    name = request.POST.get('name')
    email = request.POST.get('email')
    password = request.POST.get('password')
    password2 = request.POST.get('password2')

    if not name or not email or not password or not password2:
        messages.error(request, 'Campos vazios')
        return render(request, 'cadastro/register.html')

    try:
        validate_email(email)
    except:
        messages.error(request, 'Email inválido')
        return render(request, 'cadastro/register.html')

    if len(password) < 6:
        messages.error(request, 'Senha muito curta')
        return render(request, 'cadastro/register.html')

    if len(name) < 6:
        messages.error(request, 'Usuário muito curto')
        return render(request, 'cadastro/register.html')

    if password != password2:
        messages.error(request, 'Senhas não coincidem ')
        return render(request, 'cadastro/register.html')

    if User.objects.filter(username=name).exists():
        messages.error(request, 'Usuário existente')
        return render(request, 'cadastro/register.html')

    if User.objects.filter(email=email).exists():
        messages.error(request, 'Email existente')
        return render(request, 'cadastro/register.html')

    messages.success(request, 'Registrado com sucesso')

    user = User.objects.create_user(username=name, email=email, password=password)
    user.save()

    return redirect('login')


def login(request):
    if request.method != 'POST':
        return render(request, 'cadastro/login.html')

    name = request.POST.get('name')
    password = request.POST.get('password')

    user = auth.authenticate(request, username=name, password=password)

    if not user:
        messages.error(request, 'Dados inválidos')
        return render(request, 'cadastro/login.html')
    else:
        auth.login(request, user)
        messages.success(request, 'Login efetuado')
        return redirect('profile')

@login_required(redirect_field_name='/login')
def profile(request):
    return HttpResponse('Welcome the your profile')
