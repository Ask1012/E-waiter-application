import os
from flask import Flask, render_template
from sqlalchemy.exc import OperationalError

try:
    # Delay import until inside try block
    from database import create_app
    app = create_app()
except OperationalError as e:
    print("Database connection failed:", e)

    app = Flask(__name__)  # Fallback minimal app

    @app.route('/')
    def db_error():
        return render_template('error.html', message="Service not available"), 500

if __name__ == "__main__":

      # Render provides PORT env variable
    app.run(debug=True)

    port = int(os.environ.get("PORT", 5000))  # Render provides PORT env variable
    app.run(host="0.0.0.0", port=port, debug=True)

