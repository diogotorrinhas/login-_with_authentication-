from flask import Flask
from database import database
from website.views import views
from website.auth import auth
from website.service import service
from flask_jwt_extended import JWTManager
from flask_login import LoginManager 

def create_app():
    app = Flask(__name__)
    jwt = JWTManager(app)

    # Set up config -- SE for usado o comando "flask run" a configuração do 'config.py' não é carregada || usar antes 'python3 app.py'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' # Não consegue dar load pelo config.py por alguma razão
    app.config.from_object('config.DevConfig')

    # Set up DB
    from website.models import User, Reservation, Product
    database.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    # Register Blueprint
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(service, url_prefix='/')

    return app

if __name__ == '__main__':
    create_app().run()