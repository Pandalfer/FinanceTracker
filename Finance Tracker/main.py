from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from datetime import datetime
from important_functions import *

app = Flask(__name__)
app.secret_key = "your secret key"

#Configure SQL alchemy
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

oauth = OAuth(app)




#Database model ( row )
# Each user gets a unique row with a unique id
# Each user gets a class for three things, id password and username

class User(db.Model):
    # Account variables
    id = db.Column(db.Integer, primary_key=True)
    username: str = db.Column(db.String(25), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

    salaries = db.relationship('Income', backref='user', lazy=True)

    # # Personal variables
    # monthly_income = db.Column(db.Float(8), nullable=True)
    # monthly_expenses = db.Column(db.Float(8), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Transaction(db.Model):
    __abstract__ = True  # Prevents SQLAlchemy from creating a table for this class
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Income(Transaction):
    __tablename__ = "income"

class Saving(Transaction):
    __tablename__ = "saving"

class Expense(Transaction):
    __tablename__ = "expense"


#Routes
@app.route('/')
def home():
    if "username" in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


#Login
@app.route('/login', methods=['POST'])
def login():
    # Collect the info from the form
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()

    # Check if it's in the db
    if user and user.check_password(password):
        session['username'] = username
        return redirect(url_for('dashboard'))

    # Otherwise show the home page
    else:
        return render_template('index.html')

#Register
@app.route('/register', methods=['POST', 'GET'])
def register():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user:
        return render_template('index.html', error="User already exists!")
    else:
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = username
        return redirect(url_for('questions'))

@app.context_processor
def inject_user_balance():
    if "username" in session:
        user = User.query.filter_by(username=session["username"]).first()
        if user:
            total_income = db.session.query(db.func.sum(Income.amount)).filter_by(user_id=user.id).scalar() or 0
            total_expenses = db.session.query(db.func.sum(Expense.amount)).filter_by(user_id=user.id).scalar() or 0
            balance = total_income - total_expenses
            return {"user_balance": balance}
    return {"user_balance": None}


@app.route('/questions', methods=['POST', 'GET'])
def questions():
    if request.method == 'POST':
        monthly_income = request.form.get('monthly_income')
        monthly_savings = request.form.get('monthly_savings')

        if is_num(monthly_income) and is_num(monthly_savings):
            user = User.query.filter_by(username=session['username']).first()
            new_salary = Income(user_id=user.id,
                                category="Base Salary",
                                amount=float(monthly_income),
                                date=datetime.now())
            new_savings = Saving(user_id=user.id,
                                 category="Monthly Savings",
                                 amount=float(monthly_savings),
                                 date=datetime.now())
            db.session.add(new_salary)
            db.session.add(new_savings)
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            return render_template('questions.html', error="Please fill in all the fields with appropriate values!")

    return render_template('questions.html')





#Dashboard
@app.route('/dashboard')
def dashboard():
    if "username" in session:
        income = Income.query.all()
        savings = Saving.query.all()
        expenses = Expense.query.all()
        user = User.query.filter_by(username=session['username']).first()
        return render_template('dashboard.html', username=session['username'], income=income, savings=savings, expenses=expenses, user=user)
    return redirect(url_for('home'))

@app.template_filter('scientific')
def scientific_format(value):
    try:
        if isinstance(value, (int, float)):
            if len(str(abs(value))) > 7:
                return "{:.2e}".format(value)
            else:
                return value
    except ValueError:
        return value
    return value

def add_transaction(model, data):
    if "username" not in session:
        return jsonify({"success": False, "message": "User not logged in"}), 401

    if not data or "category" not in data or "amount" not in data:
        return jsonify({"success": False, "message": "Invalid data"}), 400

    if not data["category"].strip():
        return jsonify({"success": False, "message": "Category cannot be empty"}), 400

    try:
        amount = float(data["amount"])
        if amount <= 0:
            return jsonify({"success": False, "message": "Amount must be greater than zero"}), 400
    except ValueError:
        return jsonify({"success": False, "message": "Invalid amount"}), 400

    user = User.query.filter_by(username=session["username"]).first()
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    try:
        transaction = model(
            user_id=user.id,
            category=data["category"].strip(),
            amount=amount,
        )

        db.session.add(transaction)
        db.session.commit()

        return jsonify({"success": True, "message": f"{model.__name__} added successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500

@app.route('/add_income', methods=['POST'])
def add_income():
    return add_transaction(Income, request.get_json())

@app.route('/add_saving', methods=['POST'])
def add_saving():
    return add_transaction(Saving, request.get_json())

@app.route('/add_expense', methods=['POST'])
def add_expense():
    return add_transaction(Expense, request.get_json())

def delete_transaction(model, transaction_id):
    if "username" not in session:
        return jsonify({"success": False, "message": "User not logged in"}), 401

    user = User.query.filter_by(username=session["username"]).first()
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    transaction = model.query.filter_by(id=transaction_id, user_id=user.id).first()
    if not transaction:
        return jsonify({"success": False, "message": f"{model.__name__} entry not found"}), 404

    try:
        db.session.delete(transaction)
        db.session.commit()
        return jsonify({"success": True, "message": f"{model.__name__} entry deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500

@app.route('/delete_income/<int:income_id>', methods=['DELETE'])
def delete_income(income_id):
    return delete_transaction(Income, income_id)

@app.route('/delete_saving/<int:saving_id>', methods=['DELETE'])
def delete_saving(saving_id):
    return delete_transaction(Saving, saving_id)

@app.route('/delete_expense/<int:expense_id>', methods=['DELETE'])
def delete_expense(expense_id):
    return delete_transaction(Expense, expense_id)

#Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))


if __name__ in "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)