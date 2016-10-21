INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.admin',
    'django.contrib.sitemaps',
    'multisiteauth',
]

# TEST_RUNNER = 'django_nose.NoseTestSuiteRunner'
STATIC_ROOT = '/static/'
STATIC_URL = '/static/'
ROOT_URLCONF = 'multisiteauth.tests.urls'
TEMPLATE_CONTEXT_PROCESSORS = [
    "django.contrib.auth.context_processors.auth",
    'django.contrib.messages.context_processors.messages',
    "django.core.context_processors.i18n",
    "django.core.context_processors.debug",
    "django.core.context_processors.request",
    "django.core.context_processors.media",
    'django.core.context_processors.csrf',
    "django.core.context_processors.static",
]
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME' : ':memory:',
    }
}
MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',

    # 'cms_templates.middleware.SiteIDPatchMiddleware',
    # 'cms_templates.middleware.DBTemplatesMiddleware',

    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'multisiteauth.middleware.BasicAuthProtectionMiddleware',
)
SITE_ID = 1
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
)

SECRET_KEY = 'h34Ejc8ErE88UejQ012WQldnE3rEjCdd'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'DEBUG',
    },
    'loggers': {
        'django.request': {
            'level': 'DEBUG',
            'propagate': True,
        },
        'django.security': {
            'level': 'DEBUG',
            'propagate': False,
        },
        'django.db.backends': {
            'level': 'ERROR',
            'propagate': False,
        },
    }
}
