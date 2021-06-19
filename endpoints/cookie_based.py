from flask import Blueprint, session
from methods.token import token_validate, token_issue
from . import is_api, cors_allow

cookie_blueprint = Blueprint('Cookie-Based', __name__)


@cookie_blueprint.route('/setting', methods=['GET', 'OPTIONS'])
@cors_allow()
@is_api()
def set_cookie(data):
    status, user_token, user_uuid = token_issue()
    session['user_token'] = user_token

    if not status:
        return {'error': 'error_on_setting_cookie'}, 500
    else:
        return {'uuid': str(user_uuid)}, 200


@cookie_blueprint.route('/validate', methods=['GET', 'OPTIONS'])
@cors_allow()
@is_api()
def validate(data):
    if 'user_token' not in session:
        return {'error': 'no_permission'}, 403
    user_token = session['user_token']

    status, result = token_validate(user_token)

    if not status:
        return {'error': 'no_permission'}, 403
    else:
        return {'uuid': result}, 200
