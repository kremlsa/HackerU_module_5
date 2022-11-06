import subprocess
import bleach
import hashlib
from os import error, popen
from flask import Flask,redirect,request, render_template,session,url_for,session
from flask_sqlalchemy import SQLAlchemy
app = Flask (__name__)
app.secret_key = 'Small HackerU vulnerable app secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prod.db'
db = SQLAlchemy(app)

APP_NAME = 'Small HackerU vulnerable app'

CONFIG = {
    'app_name' : APP_NAME
}

# Fix Uncontrolled command line vulnerability
def rp(command):
    out = subprocess.Popen(['nslookup', command], stdout=subprocess.PIPE, shell=False).communicate()[0]
    return out.decode("cp437")


class User(db.Model):
  """ Create user table """
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(80), unique=True)
  password = db.Column(db.String(80))

  def __init__(self, username, password):
    self.username = username
    self.password = hashlib.sha256(password.encode()).hexdigest()


@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template('index.html', CONFIG=CONFIG)


@app.route('/login', methods=['GET', 'POST'])
def login():
  """Login Form"""
  if request.method == 'GET':
    return render_template('login.html')
  else:
    name = request.form['username']
    passw = request.form['password']
    try:
      data = User.query.filter_by(username=name, password=hashlib.sha256(passw.encode()).hexdigest()).first()
      if data is not None:
        session['logged_in'] = True
        session['username'] = name
        return redirect(url_for('home'))
      else:
        return render_template('login.html', error='Incorrect loging/password')
    except:
      return render_template('login.html', error='Incorrect loging/password')

@app.route('/register/', methods=['GET', 'POST'])
def register():
  """Register Form"""
  if request.method == 'POST':
    new_user = User(username=request.form['username'], password=request.form['password'])
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))
  return render_template('register.html')

@app.route("/logout")

def logout():
    if session['logged_in']:
      """Logout Form"""
      session['logged_in'] = False
      return redirect(url_for('home'))
    else:
        return redirect('error.html')
  

@app.errorhandler(404)
def page_not_found_error(error):
    return render_template('error.html')

# Fix Code injection
@app.route('/api/user', methods = ['GET'])
def evaluate():
    if session['logged_in']:
        data = request.args.get('user')
        result = bleach.clean(str(data))
        return str(result)
    else:
        return redirect('error.html')
 
@app.route('/what_ip', methods = ['POST', 'GET'])
def what_ip():
    if session['logged_in']:
        address = None
        if request.method == 'POST':
            address = request.form['address']
        return """
        <html>
        <link rel= "stylesheet" type= "text/css" href="/static/styles/board.css"">
           <body>
           <div class="wrapper">
              <form action = "/what_ip" method = "POST">
                 <h1>What IP</h1>
                 <p><h3>Enter address to know ip</h3></p>
                 <p><input type = 'text' name = 'address'/></p>
                 <p><input type = 'submit' value = 'Lookup'/></p>
              </form>
             """ + "Result:\n<br>\n" + (rp(address).replace('\n', '\n<br>')  if address else "") + """
           <a style="text-align:right" href="/">Go back</a>
           </div>
           </body>
        </html>
        """
    else:
        return redirect('error.html')

@app.route('/list_users', methods = ['GET'])
def list_users():
    if session['logged_in']:
        return render_template('users.html', users=User.query.all())
    else:
        return redirect('error.html')



if __name__ == "__main__":
  app.debug = False
  with app.app_context():
    db.create_all()
  app.run(host="0.0.0.0", port=8888)
