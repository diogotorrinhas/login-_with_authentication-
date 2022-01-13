from flask import Blueprint, redirect, url_for, request, flash
from sqlalchemy.sql.expression import false
from .models import Product, Reservation
from flask_login import login_required, current_user
from database.database import db
from .views import isadmin

service = Blueprint('service', __name__)

@service.route('/remove', methods=['POST'])
@login_required
def remove():
    # Check if user is admin
    if not isadmin():
        #flash("Only admin can make this request!", category="error")
        #return redirect(url_for("views.home"))
        return {"error": "Only admin can make this request!"}

    product_id = request.args.get('id')
    #verificar se o valor introduzido na query é um inteiro
    if not product_id.isnumeric():
        flash("Invalid request!", category="error")
        return redirect(url_for("views.home"))

    # Check in db if product with this id exists
    product = Product.query.filter_by(id = product_id).first() 
    if product:
        # Check if product is available, Reduce quantity by 1 and mark it as unavailable if quantity is now 0
        if product.availability:
            product.quantity = product.quantity -1
            if product.quantity == 0:
                product.availability = False
        elif product.reservations == []:
            #if not remove the product if it has no reservations
            db.session.delete(product) 
        else:
            flash("Item was not removed because there are pending reservations", category="error")
            return redirect(request.referrer)
        db.session.commit()
    else:
        flash("there is no product with that id!", category="error")
        return redirect(request.referrer)
    
    flash("Item removed!", category="success")
    return redirect(request.referrer)

@service.route('/add', methods=['POST'])
@login_required
def add():
    # Check if user is admin
    if not isadmin():
        flash("Only admin can make this request!", category="error")
        return redirect(url_for("views.home"))

    product_id = request.args.get('id')
    #verificar se o valor introduzido na query é um inteiro
    if not product_id.isnumeric():
        flash("invalid request!", category="error")
        return redirect(url_for("views.home"))

    product = Product.query.filter_by(id = product_id).first() 
    # Check in db if product with this id exists
    if product:
        #Increase quantity by 1
        product.quantity = product.quantity + 1
            # if quantity is now 1, mark the product as available
        if not product.availability:
            product.availability = True
        db.session.commit()
    else:
        flash("there is no product with that id!", category="error")
        return redirect(request.referrer)
    
    flash("Item added!", category="success")
    return redirect(request.referrer)

@service.route('/reserve', methods=['POST'])
@login_required
def reserve():
    # Get user_id
    user_id = current_user.get_id()

    # Check if is normal user:
    if isadmin():
        flash("Only normal users can make this request!", category="error")
        return redirect(url_for("views.home"))

    product_id = request.args.get('id')
    #verificar se o valor introduzido na query é um inteiro
    if not product_id.isnumeric():
        flash("invalid request!", category="error")
        return redirect(url_for("views.home"))

    # Check in db if product with this id exists
    product = Product.query.filter_by(id = product_id).first()
    # Check if product is available
    if product:       
    # Add reservation to DB
        if product.availability:
                reservation = Reservation.query.filter_by(user_id = user_id, product_id = product_id).first()
                if reservation:
                    reservation.quantity = reservation.quantity + 1
                else:    
                    new_reservation = Reservation(user_id = user_id, product_id = product_id,quantity = 1)
                    # Reduce quantity of product by 1 and mark it as unavailable if quantity = 0 
                    db.session.add(new_reservation)    

                product.quantity = product.quantity - 1
                if product.quantity == 0:
                    product.availability = False
        db.session.commit()
    else:
        flash("there is no product with that id!", category="error")
        return redirect(request.referrer)
    
    flash("Item reserved!", category="success")
    return redirect(request.referrer)

@service.route('/cancel', methods=['POST'])
@login_required
def cancel():
    # Get user_id
    user_id = current_user.get_id()

    # Check if is normal user:
    if isadmin():
        flash("Only normal user can make this request!", category="error")
        return redirect(url_for("views.home"))

    product_id = request.args.get('id')
    #verificar se o valor introduzido na query é um inteiro
    if not product_id.isnumeric():
        flash("invalid request!", category="error")
        return redirect(url_for("views.home"))
    
    product = Product.query.filter_by(id = product_id).first()
    # if product exists
    if product:
        reservation = Reservation.query.filter_by(user_id = user_id, product_id = product_id).first()
        # if there is any reservation
        if reservation:
            # if there is only one reservation remove it from Reservation
            if reservation.quantity == 1:
                db.session.delete(reservation)
            else: # decrease the quantity
                reservation.quantity = reservation.quantity - 1
            product.quantity = product.quantity + 1
            db.session.commit()
        else:
            flash ("There is not yet a reservation", category="error")
            return redirect(request.referrer)
    else:
        flash("There is no product with that id!", category="error")
        return redirect(request.referrer)

    flash("Reservation canceled!", category="success")
    return redirect(request.referrer)

