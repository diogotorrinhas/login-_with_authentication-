from flask import Blueprint, render_template, request, redirect, url_for, flash, make_response
from flask_login import current_user, login_required
from database.database import db
from .models import Product, User, Reservation

views = Blueprint('views', __name__, template_folder="templates/")

@views.route("/")
def home():
    query = request.args.get('q') # string que o utilizador pesquisou
    products = [] # lista com os produtos a retornar

    #Não permitir pesquisas de strings vazias
    if query == "":
        return redirect(url_for("views.home"))
    # Procurar na db por produtos que correspondam à pesquisa e adicioná-los à lista *products*    
    elif query:
        from .models import Product
        product_list = Product.query.all()
        for product in product_list:
            # Show only available products for normal users
            if not isadmin():
                if (query.lower() in product.name.lower() or query.lower() in product.description.lower()) and product.availability == True:
                    product.image_url = "../static/assets/" + product.image_url
                    products.append(product)
            # Show every product for admin user
            else:
                if (query.lower() in product.name.lower() or query.lower() in product.description.lower()):
                    product.image_url = "../static/assets/" + product.image_url
                    product.quantity = product.quantity + sum(map(lambda r: r.quantity, Reservation.query.filter_by(product_id=product.id)))
                    products.append(product)

    # verificar se o utilizador é admin
    # neste caso é admin se for o utilizador com o id 1    
    
    r = make_response(render_template('index.html', user=current_user, products=products, query=query, isadmin=isadmin()))
    return set_headers(r)

@views.route('/reservations')
@login_required
def reservations():
    # Check if is normal user:
    if int(current_user.get_id()) == 1:
        flash("Only normal user can make this request!", category="error")
        return redirect(url_for("views.home"))

    reservations = User.query.filter_by(id = int(current_user.get_id())).first().reservations
    products = []
    for r in reservations:
        product = Product.query.filter_by(id = r.product_id).first()
        product.image_url = '../static/assets/' + product.image_url
        product.quantity = r.quantity
        products.append(product)

    r = make_response(render_template('reservations.html', user=current_user, products=products, isadmin=isadmin()))
    return set_headers(r)
    
@views.route('/newproduct', methods=['GET', 'POST'])
@login_required
def newproduct():
    if not isadmin():
        flash("Only admin can access this page!", category='error')
        return redirect(url_for('views.home'))

    if request.method == 'POST':
        product_name = request.form.get('product_name')
        product_description = request.form.get('product_description')
        product_cost = request.form.get('product_cost')
        product_quantity = request.form.get('product_quantity')
        product_image = request.files['product_image']
        if product_image.filename != '':
            product_image.save('app/static/assets/' + product_image.filename)
            new_product = Product(name=product_name, cost=product_cost, availability=True, quantity=product_quantity, image_url=product_image.filename, description=product_description)
            db.session.add(new_product)
            db.session.commit()
            flash('Product added!', category='success')
            return redirect(url_for('views.home'))
        else:
            flash('Invalid Name!', category='error')

    r = make_response(render_template('newproduct.html', user=current_user, isadmin=isadmin()))
    return set_headers(r)

@views.app_errorhandler(404)
def page_not_found(e):
    flash('Page Not Foud!', category='error')
    return redirect(url_for("views.home"))

def isadmin():
    if current_user.is_authenticated:
        return True if int(current_user.get_id()) == 1 else False
    return False

def set_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response