# Internationalization support for NetWatch SIEM
import os
import json
from flask import request, session

class I18nManager:
    def __init__(self, app=None):
        self.app = app
        self.translations = {}
        self.default_language = 'en'
        self.supported_languages = ['en', 'es', 'fr', 'de', 'zh']
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the i18n manager with Flask app"""
        self.app = app
        app.config.setdefault('I18N_DEFAULT_LANGUAGE', 'en')
        app.config.setdefault('I18N_TRANSLATIONS_PATH', 'i18n/translations')
        
        self.default_language = app.config['I18N_DEFAULT_LANGUAGE']
        self.load_translations()
        
        # Add template context processor
        @app.context_processor
        def inject_i18n():
            return {
                'gettext': self.gettext,
                'current_language': self.get_current_language(),
                'supported_languages': self.supported_languages
            }
    
    def load_translations(self):
        """Load all translation files"""
        if not self.app:
            return
        
        import os
        # Get the app root directory (where app.py is located)
        app_root = self.app.root_path
        translations_path = os.path.join(app_root, 'i18n', 'translations')
        
        for lang in self.supported_languages:
            try:
                file_path = os.path.join(translations_path, f'{lang}.json')
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.translations[lang] = json.load(f)
                    print(f"Loaded translations for {lang}")
            except FileNotFoundError:
                print(f"Warning: Translation file for {lang} not found at {file_path}")
                self.translations[lang] = {}
    
    def get_current_language(self):
        """Get current language from session or request"""
        try:
            # Check session first
            if 'language' in session:
                return session['language']
            
            # Check request headers
            if request and hasattr(request, 'headers'):
                accept_language = request.headers.get('Accept-Language', '')
                for lang in self.supported_languages:
                    if lang in accept_language:
                        return lang
        except:
            pass
        
        return self.default_language
    
    def set_language(self, language):
        """Set language in session"""
        try:
            if language in self.supported_languages:
                session['language'] = language
                return True
        except:
            pass
        return False
    
    def gettext(self, key, **kwargs):
        """Get translated text for current language"""
        current_lang = self.get_current_language()
        translations = self.translations.get(current_lang, {})
        
        # Get the translation, fallback to English if not found
        text = translations.get(key, key)
        
        # If still not found in current language, try English
        if text == key and current_lang != 'en':
            english_translations = self.translations.get('en', {})
            text = english_translations.get(key, key)
        
        # Replace placeholders
        if kwargs:
            try:
                text = text.format(**kwargs)
            except (KeyError, ValueError):
                pass
        
        return text
    
    def get_available_languages(self):
        """Get list of available languages with their display names"""
        return {
            'en': 'English',
            'es': 'Español',
            'fr': 'Français',
            'de': 'Deutsch',
            'zh': '中文'
        }

# Global instance
i18n = I18nManager()
