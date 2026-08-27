from app import create_app
from flask import render_template

# 1. Initialize your app using your factory (this loads your blueprints and configs)
app = create_app()

# 2. Add your root route to the app instance
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)

