from django import forms
from django.contrib.auth.models import User
from aggregator.models import Feed

class RegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'placeholder': '••••••••',
        'class': 'soc-input block w-full px-4 py-2 border-b border-outline-variant/30 bg-transparent text-on-surface focus:outline-none focus:border-primary-fixed transition-all'
    }))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={
        'placeholder': '••••••••',
        'class': 'soc-input block w-full px-4 py-2 border-b border-outline-variant/30 bg-transparent text-on-surface focus:outline-none focus:border-primary-fixed transition-all'
    }))

    class Meta:
        model = User
        fields = ['username', 'email']
        widgets = {
            'username': forms.TextInput(attrs={
                'placeholder': 'Enter username',
                'class': 'soc-input block w-full px-4 py-2 border-b border-outline-variant/30 bg-transparent text-on-surface focus:outline-none focus:border-primary-fixed transition-all'
            }),
            'email': forms.EmailInput(attrs={
                'placeholder': 'analyst@threatshield.local',
                'class': 'soc-input block w-full px-4 py-2 border-b border-outline-variant/30 bg-transparent text-on-surface focus:outline-none focus:border-primary-fixed transition-all'
            })
        }

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("A user with that username already exists.")
        return username

    def clean(self):
        cleaned_data = super().clean()
        
        source = cleaned_data.get('source')
        url = cleaned_data.get('url')
        file_upload = cleaned_data.get('file_upload')
        
        if source == 'URL':
            if not url:
                self.add_error(
                    'url',
                    'URL is required when source type is Remote URL.'
                    )
                
            elif source == 'File Upload':
                if not file_upload:
                    self.add_error(
                        'file_upload',
                        'Please select a CSV, TXT or JSON file.'
                        )
                    return cleaned_data

class FeedForm(forms.ModelForm):
    file_upload = forms.FileField(required=False, widget=forms.FileInput(attrs={
        'class': 'hidden',
        'id': 'file-upload'
    }))

    class Meta:
        model = Feed
        fields = ['name', 'source', 'feed_type', 'category', 'description', 'url']
        widgets = {
            'name': forms.TextInput(attrs={
                'placeholder': 'e.g., Abuse.ch Botnet C2 List',
                'class': 'input-glass block w-full px-4 py-2 rounded border border-outline-variant/30 bg-surface-container/50 text-on-surface focus:outline-none focus:border-primary-fixed'
            }),
            'source': forms.Select(choices=[('URL', 'Remote URL'), ('File Upload', 'Local File Upload')], attrs={
                'class': 'input-glass block w-full px-4 py-2 rounded border border-outline-variant/30 bg-surface-container/50 text-on-surface focus:outline-none focus:border-primary-fixed'
            }),
            'feed_type': forms.Select(choices=[('CSV', 'CSV Table'), ('TXT', 'TXT List'), ('JSON', 'JSON Array/STIX')], attrs={
                'class': 'input-glass block w-full px-4 py-2 rounded border border-outline-variant/30 bg-surface-container/50 text-on-surface focus:outline-none focus:border-primary-fixed'
            }),
            'category': forms.TextInput(attrs={
                'placeholder': 'e.g., Malware IP, Phishing URL',
                'class': 'input-glass block w-full px-4 py-2 rounded border border-outline-variant/30 bg-surface-container/50 text-on-surface focus:outline-none focus:border-primary-fixed'
            }),
            'description': forms.Textarea(attrs={
                'placeholder': 'Describe the threat intelligence feed details...',
                'rows': 3,
                'class': 'input-glass block w-full px-4 py-2 rounded border border-outline-variant/30 bg-surface-container/50 text-on-surface focus:outline-none focus:border-primary-fixed'
            }),
            'url': forms.URLInput(attrs={
                'placeholder': 'https://example.com/feed.csv',
                'class': 'input-glass block w-full px-4 py-2 rounded border border-outline-variant/30 bg-surface-container/50 text-on-surface focus:outline-none focus:border-primary-fixed'
            })
        }

    def clean(self):
        cleaned_data = super().clean()
        source = cleaned_data.get('source')
        url = cleaned_data.get('url')
        file_upload = cleaned_data.get('file_upload')

        if source == 'URL' and not url:
            self.add_error('url', "URL is required when source type is Remote URL.")
        return cleaned_data
