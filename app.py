from flask import Flask
from config import FLASK_SECRET
import endpoints

app = Flask(__name__)

app.secret_key = FLASK_SECRET
app.register_blueprint(endpoints.cookie_blueprint, url_prefix='/cookie-based')
app.register_blueprint(endpoints.header_blueprint, url_prefix='/header-based')


@app.before_first_request
def print_map():
    print(app.url_map)


if __name__ == '__main__':
    app.run()
