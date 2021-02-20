from flask import render_template
from app import app, db
import sys
import traceback
from . import emailprompt

@app.errorhandler(404)
def not_found_error(error):
    #print("-"*60)
    #traceback.print_exc(file=sys.stdout)
    formatted_lines = traceback.format_exc()
    emailprompt.send_error_email(str(formatted_lines))
    #print("-"*60)
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    formatted_lines = traceback.format_exc()
    emailprompt.send_error_email(str(formatted_lines))
    db.session.rollback()
    return render_template('500.html'), 500