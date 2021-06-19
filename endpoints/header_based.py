from flask import Blueprint, request
from methods.token import token_validate, token_issue
from . import is_api, cors_allow

header_blueprint = Blueprint('Header-Based', __name__)


@header_blueprint.route('/setting', methods=['GET', 'OPTIONS'])
@cors_allow()
@is_api()
def set_token(data):
    status, user_token, user_uuid = token_issue()

    if not status:
        return {'error': 'error_on_setting_cookie'}, 500
    else:
        return {'token': user_token, 'uuid': str(user_uuid)}, 200


@header_blueprint.route('/validate', methods=['GET', 'OPTIONS'])
@cors_allow()
@is_api()
def validate(data):
    if 'Authorization' not in request.headers:
        return {'error': 'no_permission'}, 403
    user_token: str = request.headers['Authorization']
    if user_token[:5].lower() != 'token':
        return {'error': 'no_permission'}, 403
    user_token = user_token.split(' ', 1)[1]

    status, result = token_validate(user_token)

    if not status:
        return {'error': 'no_permission'}, 403
    else:
        return {'uuid': result}, 200
