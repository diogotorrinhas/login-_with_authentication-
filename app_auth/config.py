class Config(object):
    DEBUG = False
    TESTING = False
    CSFR_ENABLED = True
    SECRET_KEY = 'ljdshfkdsjhfksdfdfsdfsdfsdf' 
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevConfig(Config):
    DEBUG = True
    ENV = 'development'
    DEVELOPMENT = True
