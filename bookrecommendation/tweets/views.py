from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login,logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User

def LoginPage(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')  # Ensure this matches the input field name

        user = authenticate(request, username=username, password=password)
        

        
        if user is not None:
            print(f"User {username} authenticated successfully.")
            login(request, user)
            return redirect('home')
        else:
            print(f"Authentication failed for user {username}.")
            messages.error(request, "Invalid username or password!")  # Using messages framework for feedback
            return redirect('login')

    return render(request, 'login.html')


def SignupPage(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        # Passwords must match
        if password1 != password2:
            messages.error(request, "Your password and confirm password do not match.")
            return redirect('signup')

        # Check if password is strong enough (example: length, complexity)
        #if len(password1) < 8:
           # messages.error(request, "Password must be at least 8 characters long.")
            #return redirect('signup')

        try:
            # Create new user
            my_user = User.objects.create_user(username=username, email=email, password=password1) 
            my_user.is_active=True
            my_user.save()
            messages.success(request, "Account created successfully! Please log in.")
            return redirect('login')
        except Exception as e:
            messages.error(request, f"Error: {str(e)}")
            return redirect('signup')

    return render(request, 'signup.html')

@login_required(login_url='login')  # Redirect to login page if not authenticated
def HomePage(request):
    return render(request, 'home.html')


def LogoutPage(request):
    logout(request)
    return redirect('login')



