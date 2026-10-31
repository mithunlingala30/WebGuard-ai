"""
A deliberately weak, LOCAL-ONLY test website for validating WebGuard AI.

It contains harmless, intentionally planted weaknesses (no real secrets, in-memory data):
  * no security headers, cookies without Secure/HttpOnly/SameSite
  * /search?q=  reflects input without encoding        (reflected XSS)
  * /product?name=  concatenates input into a SQLite query and prints DB errors (SQL injection)
  * /files/  directory listing, /.env fake configuration, Server version banner

Run:   python tests/vuln_test_site.py          (listens on http://127.0.0.1:5001)
Never expose this to a network.
"""
import sqlite3
import sys

from flask import Flask, make_response, request

app = Flask(__name__)

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
_db.executemany("INSERT INTO products (name, price) VALUES (?, ?)", [("apple", 1.2), ("banana", 0.5), ("cherry", 3.0)])
_db.commit()

PAGE = "<!doctype html><html><head><title>Test Shop</title></head><body>{}</body></html>"


@app.after_request
def banner(resp):
    resp.headers["Server"] = "TestShop/1.4.2"
    resp.headers["X-Powered-By"] = "Flask-Demo/0.9"
    return resp


@app.route("/")
def home():
    body = ('<h1>Test Shop</h1><a href="/product?name=apple">Apple</a> <a href="/about">About</a>'
            '<form action="/search" method="get"><input type="text" name="q"><input type="submit" value="Go"></form>')
    resp = make_response(PAGE.format(body))
    resp.headers.add("Set-Cookie", "sessionid=abc123; Path=/")
    return resp


@app.route("/about")
def about():
    return PAGE.format("<p>About this lab site.</p><a href='/'>Home</a>")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return PAGE.format(f"<h2>Results</h2><div>You searched for {q}</div>")          # intentionally unencoded


@app.route("/product")
def product():
    name = request.args.get("name", "")
    try:
        rows = _db.execute(f"SELECT id, name, price FROM products WHERE name = '{name}'").fetchall()   # intentionally unsafe
    except sqlite3.Error as exc:
        return PAGE.format(f"<pre>sqlite3.OperationalError: {exc}</pre>"), 500
    return PAGE.format("<ul>" + "".join(f"<li>{r[1]} - ${r[2]}</li>" for r in rows) + "</ul>")


@app.route("/files/")
def files():
    return "<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1><a href='..'>Parent Directory</a></body></html>"


@app.route("/.env")
def env():
    return "APP_NAME=lab\nAPP_DEBUG=true\nDEMO_KEY=not-a-real-secret\n", 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5001
    app.run(host="127.0.0.1", port=port, debug=False)
