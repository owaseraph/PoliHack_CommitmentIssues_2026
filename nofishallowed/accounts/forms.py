from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)
    skip_validation = forms.BooleanField(
        required=False,
        label='Disable password validation (dev only)',
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

    def clean_password2(self):
        p1 = self.cleaned_data.get('password1', '')
        p2 = self.cleaned_data.get('password2', '')
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("The two password fields didn't match.")
        return p2

    def _post_clean(self):
        # Skip Django's built-in password validators when the checkbox is ticked
        if self.data.get('skip_validation'):
            try:
                self.instance.username = self.cleaned_data.get('username', '')
            except Exception:
                pass
            return
        super()._post_clean()

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user


class LoginForm(AuthenticationForm):
    pass