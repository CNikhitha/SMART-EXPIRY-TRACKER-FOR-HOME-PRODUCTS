# Deployment Guide

## Local Development

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application:**
   ```bash
   python app.py
   ```

3. **Access the application:**
   Open your browser and navigate to `http://localhost:5000`

## Production Deployment

### Option 1: Using Gunicorn (Recommended)

1. **Install Gunicorn:**
   ```bash
   pip install gunicorn
   ```

2. **Run with Gunicorn:**
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

### Option 2: Deploy to Heroku

1. **Install Heroku CLI** and login:
   ```bash
   heroku login
   ```

2. **Create a new Heroku app:**
   ```bash
   heroku create your-app-name
   ```

3. **Set environment variables:**
   ```bash
   heroku config:set SECRET_KEY=your-production-secret-key
   ```

4. **Deploy:**
   ```bash
   git push heroku main
   ```

### Option 3: Deploy to Railway

1. **Connect your repository** to Railway
2. **Set environment variables** in Railway dashboard:
   - `SECRET_KEY`: Your production secret key
3. **Railway will automatically detect** the Procfile and deploy

### Option 4: Deploy to Render

1. **Create a new Web Service** on Render
2. **Connect your repository**
3. **Set build command:** `pip install -r requirements.txt`
4. **Set start command:** `gunicorn -w 4 -b 0.0.0.0:$PORT app:app`
5. **Set environment variables:**
   - `SECRET_KEY`: Your production secret key

### Option 5: Deploy to PythonAnywhere

1. **Upload your files** to PythonAnywhere
2. **Create a new web app** and select Flask
3. **Set the working directory** to your project folder
4. **Update WSGI configuration** to point to `app:app`
5. **Reload the web app**

## Important Security Notes

⚠️ **Before deploying to production:**

1. **Change the SECRET_KEY** in `app.py`:
   ```python
   app.config['SECRET_KEY'] = 'your-strong-random-secret-key-here'
   ```
   Generate a strong secret key:
   ```python
   import secrets
   print(secrets.token_hex(32))
   ```

2. **Use environment variables** for sensitive data:
   ```python
   import os
   app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-key')
   ```

3. **Enable HTTPS** in production

4. **Set up proper database backups** if using SQLite (consider PostgreSQL for production)

## Database Migration

The database is automatically created on first run. For production, consider:

1. **Using PostgreSQL** instead of SQLite:
   ```python
   app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///expiry_products.db')
   ```

2. **Setting up database migrations** with Flask-Migrate:
   ```bash
   pip install Flask-Migrate
   ```

## Environment Variables

Create a `.env` file (don't commit this):
```
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///expiry_products.db
FLASK_ENV=production
```

## Troubleshooting

- **Port already in use:** Change the port in `app.py` or use environment variable `PORT`
- **Database errors:** Delete `expiry_products.db` and restart the app
- **Import errors:** Ensure all dependencies are installed: `pip install -r requirements.txt`

