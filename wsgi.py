from flask import Flask, render_template
from sqlalchemy.exc import OperationalError

try:
    # Delay import until inside try block
    from database import create_app
    app = create_app()
except OperationalError as e:
    print("Database connection failed:", e)
    
    app = Flask(__name__)  # Create fallback app

    @app.route('/')
    def db_error():
        return render_template('error.html',message="service not available "), 500

if __name__ == "__main__":
    app.run(debug=True)
