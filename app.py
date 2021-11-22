from flask import Flask, g
from flask import jsonify
from flask import render_template
from flask_cors import CORS
from flask_admin import Admin
from flask_expects_json import expects_json
from models.data_models import AdminUser, ProfileQuestionnaire
from models.constants import GenderType, CountryCode
from authentication.auth_blueprint import auth_blueprint
from authentication import authentication_required
from models import data_models as dm
from models.data_models import db
from datetime import datetime
from flask import abort
import os


template_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'templates')
app = Flask(__name__, template_folder=template_dir)
app.name = "Equalgen"
app_settings = os.getenv('APP_SETTINGS', 'config.DevelopmentConfig')
app.config.from_object(app_settings)
db.init_app(app)
dm.bcrypt.init_app(app)
dm.basic_auth.init_app(app)


def create_and_add_admin_users_to_database(config):
    for admin_info in config["API_ADMINS"]:
        if db.session.query(AdminUser).filter(AdminUser.email == admin_info["email"]).first() is None:
            db.session.add(AdminUser(**admin_info))
    db.session.commit()


@app.errorhandler(404)
def not_found_error(error):
    return render_template('error/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error/500.html'), 500


@app.route('/questionnaire/view', methods=['GET'])
def view_questions_list():
    with app.app_context():
        questionnaires = db.session.query(dm.Questionnaire).all()
        return render_template('questionnaire/list.html', questionnaires=questionnaires)


@app.route('/questionnaire/<int:questionnaire_id>/view', methods=['GET'])
def view_questionnaire(questionnaire_id=0):
    with app.app_context():
        questionnaire = db.session.query(dm.Questionnaire).filter(dm.Questionnaire.id == questionnaire_id).first()
        if questionnaire is None:
            abort(404)
        return render_template('questionnaire/view.html', questionnaire=questionnaire)


@app.route('/questionnaire/create', methods=['POST'])
@expects_json({
    'type': 'object',
    'properties': {
        'title': {'type': 'string'}
    },
    'required': ['title']
})
@authentication_required
def create_questionnaire(current_user: AdminUser):
    data = g.data
    app.logger.info("Create Questionnaire")
    app.logger.debug("Request=({})".format(data))

    with app.app_context():
        questionnaire = dm.Questionnaire(title=data['title'])
        db.session.add(questionnaire)
        db.session.commit()
        return jsonify({'error': False, 'questionnaireData': {"questionnaireID": questionnaire.id}}), 200

    return jsonify({'error': True, 'errorMessage': 'Unable to create new questionnaire.'}), 500


@app.route('/user/create', methods=['POST'])
@expects_json({
    'type': 'object',
    'properties': {
        'username': {'type': 'string', 'minLength': 2, 'maxLength': 50},
        'firstname': {'type': 'string', 'minLength': 2, 'maxLength': 255},
        'lastname': {'type': 'string', 'minLength': 2, 'maxLength': 255},
        'gender': {'type': 'string', 'minLength': 1, 'maxLength': 1},  # TODO: convert to enum
        'birthday': {'type': 'string'},
        'email': {'type': 'string'},
        'password': {'type': 'string'},
        'profile_image_path': {'type': 'string'}
    },
    'required': ['username', 'firstname', 'lastname', 'gender', 'birthday', 'email', 'password']
})
def create_user():
    data = g.data
    app.logger.info("Create Questionnaire")
    app.logger.debug("Request=({})".format(data))

    with app.app_context():
        birthday = datetime.fromisoformat(data['birthday'] + " 00:00:00")
        country = CountryCode.AUSTRIA  # FIXME: convert enum
        gender = dm.GenderType.FEMALE  # FIXME: convert enum
        user = dm.User(username=data['username'], firstname=data['firstname'], lastname=data['lastname'],
                       gender=gender, birthday=birthday, country=country, email=data['email'],
                       password=data['password'])
        user.profile_image_path = data.get('profile_image_path', None)
        #ProfileQuestionnaire(gender)
        db.session.add(user)
        db.session.commit()
        return jsonify({'error': False, 'userData': {"userID": user.id}}), 200

    return jsonify({'error': True, 'errorMessage': 'Unable to create new user.'}), 500


@app.route('/user/password/change', methods=['POST'])
@expects_json({
    'type': 'object',
    'properties': {
        'userID': {'type': 'integer'},
        'oldPassword': {'type': 'string'},
        'newPassword': {'type': 'string'}
    },
    'required': ['userID', 'oldPassword', 'newPassword']
})
@authentication_required
def change_password():
    data = g.data
    app.logger.info("Change user password")
    app.logger.debug("Request=({})".format(data))

    with app.app_context():
        user = db.session.query(dm.User).filter(dm.User.id == data['userID']).first()
        if user is None:
            abort(404)

        if user.password != data['oldPassword']:
            return jsonify({'error': True, 'errorMessage': 'Old password is incorrect.'}), 400

        user.password = data['newPassword']
        db.session.add(user)
        db.session.commit()
        return jsonify({'error': False, 'userData': {"userID": user.id}}), 200

    return jsonify({'error': True, 'errorMessage': 'Unable to create new user.'}), 500

# TODO: upload image request


@app.route('/user/delete', methods=['POST'])
@expects_json({
    'type': 'object',
    'properties': {
        'userID': {'type': 'integer'},
        'reason': {'type': 'string'}              # TODO: convert to enum
    },
    'required': ['userID', 'reason']
})
# FIXME: authentication required!!
#@authentication_required
def delete_account():
    data = g.data
    app.logger.info("Delete user account")
    app.logger.debug("Request=({})".format(data))

    with app.app_context():
        user = db.session.query(dm.User).filter(dm.User.id == data['userID']).first()
        if user is None:
            abort(404)

        # TODO: convert reason to enum!
        user.delete_account(reason=dm.DeleteReasonType.OTHER)
        db.session.add(user)
        db.session.commit()
        return jsonify({'error': False, 'userData': {"userID": user.id}}), 200

    return jsonify({'error': True, 'errorMessage': 'Unable to create new user.'}), 500


def create_app():
    CORS(app)
    app.secret_key = app.config['SECRET_KEY']
    #helper.setup_logging(app, logging.INFO, paths_and_line_numbers=False)
    #helper.init_config(app)

    with app.app_context():
        dm.db.create_all()

        # TODO: default entries (e.g., standard questionnaires, etc.)
        questionnaire = ProfileQuestionnaire(title='Profile Questionnaire', questionnaire_type=GenderType.MALE)
        questionnaire.questions = []
        #db.session.add(questionnaire)

        dm.db.session.commit()
        create_and_add_admin_users_to_database(app.config)

    admin = Admin(app, name='Logbook', template_mode='bootstrap3')
    admin.add_view(dm.StandardModelView(dm.Questionnaire, dm.db.session))
    admin.add_view(dm.StandardModelView(dm.Question, dm.db.session))

    app.register_blueprint(auth_blueprint)
    return app


def main():
    flask_app = create_app()
    if app_settings.endswith("ProductionConfig"):
        flask_app.run(host='0.0.0.0', port=9002, debug=False)
    else:
        flask_app.run(host='0.0.0.0', port=9002, debug=True)


if __name__ == '__main__':
    main()
