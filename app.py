import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__, static_url_path='/static', static_folder='static')

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Get the user id
    user_id = session["user_id"]

    # Get the user's cash balance
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    # Get the user's stocks and shares
    stocks = db.execute("""
        SELECT symbol, SUM(shares) as total_shares
        FROM transactions
        WHERE user_id = ?
        GROUP BY symbol
        HAVING total_shares > 0
    """, user_id)

    # Initialize portfolio and grand total
    portfolio = []
    grand_total = cash

    # Loop through all the stocks
    for stock in stocks:
        symbol = stock["symbol"]
        shares = stock["total_shares"]

        # Get current stock info
        stock_info = lookup(symbol)

        # Calculate total value of holding
        total_value = shares * stock_info["price"]
        grand_total += total_value

        # Add stock info to portfolio
        portfolio.append({
            "symbol": symbol,
            "name": stock_info["name"],
            "shares": shares,
            "price": stock_info["price"],
            "total": total_value
        })

    # Render the index page with portfolio info
    return render_template("index.html", portfolio=portfolio, cash=cash, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # if the user submits a form
    if request.method == "POST":

        # if symbol not entred
        if not request.form.get("symbol"):
            return apology("Must provide a symbol", 403)

        # if number of shares not entred
        elif not request.form.get("shares"):
            return apology("Must provide number of shares to buy", 403)

        # if the entred symbol does not match return apology
        stock = lookup(request.form.get("symbol"))
        if stock is None:
            return apology("Stock symbol does not match", 403)


        price = stock["price"]
        shares = int(request.form.get("shares"))

        # check for the cash user currently have
        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        if cash < (price * shares):
            return apology("Not enough cash")


        # to deduct amount after purchase and show transcations in DB
        total_cost = price * shares
        new_cash = cash - total_cost
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)

        # record the transactions in db
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES(?, ?, ?, ?)", user_id, stock["symbol"], shares, price)

        # redirect to homepage after buying
        return redirect("/")

    # else the user is getting/visiting the page
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Get the user id
    user_id = session["user_id"]

    # Query all transactions for the user
    transactions = db.execute("""
        SELECT symbol, shares, price, transacted
        FROM transactions
        WHERE user_id = ?
        ORDER BY transacted DESC
    """, user_id)

    # Render the history page with transaction data
    return render_template("history.html", transactions=transactions)



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    #if user submits the form (i.e POST)
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("Must provide the stock symbol", 403)

        # Using lookup function to look for stock quote
        stock = lookup(request.form.get("symbol"))

        # if stock does not exists
        if stock is None:
            return apology("Stock does not exists", 403)

        else:
            print(stock)
            return render_template("quoted.html", price=stock["price"], symbol=stock["symbol"])
    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # confirm the password
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if password != confirmation:
            return apology("passwords do not match", 403)

        hashed_password = generate_password_hash(password)
        # insert the username and password into Db and check is it unique or not
        try:
            # Attempt to insert the new user
            username = request.form.get("username")
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)
            return redirect("/login")
        except ValueError:
            # Handle the error if the username already exists
            return apology("username already exists", 400)

    else:
        return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Get the user id
    user_id = session["user_id"]

    if request.method == "POST":
        # Get form inputs
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Check if symbol is selected
        if not symbol:
            return apology("Must select a stock to sell", 403)

        # Check if shares is a positive integer
        try:
            shares = int(shares)
            if shares <= 0:
                raise ValueError
        except ValueError:
            return apology("Shares must be a positive integer", 403)

        # Check if user owns the stock
        stock = db.execute("""
            SELECT SUM(shares) as total_shares
            FROM transactions
            WHERE user_id = ? AND symbol = ?
            GROUP BY symbol
        """, user_id, symbol)

        if not stock or stock[0]["total_shares"] < shares:
            return apology("Not enough shares to sell", 403)

        # Lookup current stock price
        stock_info = lookup(symbol)
        if stock_info is None:
            return apology("Stock symbol does not exist", 403)

        # Calculate the total sale value
        price = stock_info["price"]
        sale_value = price * shares

        # Update user's cash balance
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        new_cash = cash + sale_value
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)

        # Update transaction records (negative shares to indicate selling)
        db.execute("""
            INSERT INTO transactions (user_id, symbol, shares, price)
            VALUES(?, ?, ?, ?)
        """, user_id, symbol, -shares, price)

        # Redirect to home page
        return redirect("/")

    else:
        # Get all stocks the user owns for the dropdown
        stocks = db.execute("""
            SELECT symbol
            FROM transactions
            WHERE user_id = ?
            GROUP BY symbol
            HAVING SUM(shares) > 0
        """, user_id)

        return render_template("sell.html", stocks=stocks)



@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    """Change user password"""
    if "user_id" not in session:
        return redirect("/login")  # Redirect to login if not logged in

    user_id = session["user_id"]
    
    if request.method == "POST":
        password = request.form.get("password")
        newpassword = request.form.get("newpassword")
        confirmation = request.form.get("confirmation")

        # Ensure old password was submitted
        if not password:
            return apology("Must provide password", 400)

        # Ensure new password was submitted
        elif not newpassword:
            return apology("Must provide new password", 400)

        # Ensure new passwords match
        elif newpassword != confirmation:
            return apology("Passwords do not match!", 400)

        rows = db.execute("SELECT * FROM users WHERE id = ?", user_id)

        # Ensure user exists and old password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("Incorrect password!", 403)

        # Update user's password
        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(newpassword), user_id)

        flash("Password change successful!")
        return redirect("/")  # Redirect to homepage

    else:
        return render_template("change_password.html")
