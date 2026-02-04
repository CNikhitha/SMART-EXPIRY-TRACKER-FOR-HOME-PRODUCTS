# SMART-EXPIRY-TRACKER-FOR-HOME-PRODUCTS

A comprehensive full-stack web application for managing product expiry dates with automatic deletion, analytics, and beautiful UI.

## Features

- **User Authentication**: Secure sign up, sign in, and sign out with bcrypt password hashing
- **Product Management**: Add, view, and delete products with expiry tracking
- **Automatic Expiry Handling**: Expired products are automatically deleted
- **Manual Deletion**: Delete products manually at any time
- **Analytics Dashboard**: Visual charts and graphs using Matplotlib
- **Monthly Tracking**: Track products by purchase and expiry months
- **Beautiful UI**: Modern, responsive design with animations and transitions
- **Data Visualization**: Charts showing product status, trends, and expiring products

## Tech Stack

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, JavaScript
- **Database**: SQLite (SQL)
- **Authentication**: bcrypt
- **Data Analysis**: NumPy, Pandas, Matplotlib
- **Deployment**: Gunicorn (included)

## Installation

1. **Clone or navigate to the project directory**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Access the application**:
   Open your browser and navigate to `http://localhost:5000`

## Project Structure

```
SET_PROJECT/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/            # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── signup.html
│   ├── dashboard.html
│   ├── add_product.html
│   └── analytics.html
├── static/               # Static files
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── main.js
└── README.md
```

## Usage

1. **Sign Up**: Create a new account with username, email, and password
2. **Sign In**: Log in with your credentials
3. **Add Products**: Add products with Product ID, Name, Purchase Date, and Expiry Date
4. **View Dashboard**: See all your products with status indicators
5. **Analytics**: View charts and statistics about your products
6. **Delete Products**: Manually delete products or let the system auto-delete expired ones

## Database Schema

### Users Table
- id (Primary Key)
- username (Unique)
- email (Unique)
- password_hash
- created_at

### Products Table
- id (Primary Key)
- product_id
- product_name
- purchase_date
- expiry_date
- user_id (Foreign Key)
- created_at

## Deployment

### For Production Deployment:

1. **Update SECRET_KEY** in `app.py`:
   ```python
   app.config['SECRET_KEY'] = 'your-production-secret-key-here'
   ```

2. **Deploy using Gunicorn**:
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

3. **For platforms like Heroku, Railway, or Render**:
   - Add a `Procfile` with: `web: gunicorn -w 4 -b 0.0.0.0:$PORT app:app`
   - Set environment variables as needed
   - The application will automatically create the database on first run

## Features in Detail

### Authentication
- Secure password hashing using bcrypt
- Session management with Flask-Login
- Protected routes requiring authentication

### Product Management
- CRUD operations for products
- Automatic expiry detection
- Status indicators (Active, Expiring Soon, Expired)
- Days until expiry calculation

### Analytics
- Pie chart: Products by expiry status
- Bar chart: Products expiring in next 30 days
- Trend chart: Monthly purchase and expiry patterns
- Statistical summaries

### UI/UX
- Responsive design for all devices
- Smooth animations and transitions
- Modern gradient backgrounds
- Intuitive navigation
- Flash messages for user feedback

## Security Notes

- Passwords are hashed using bcrypt
- SQL injection protection via SQLAlchemy ORM
- Session-based authentication
- User-specific data isolation

## License

This project is open source and available for use.

## Support

For issues or questions, please check the code comments or create an issue in the repository.

