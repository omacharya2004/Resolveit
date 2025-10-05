# Google OAuth Setup Guide for ResolveIt

## 🚀 Overview
This guide will help you set up Google OAuth authentication for your ResolveIt complaint management system, allowing users to sign in and register using their Google accounts.

## 📋 Prerequisites
- Google Cloud Console account
- ResolveIt application deployed or running locally
- Access to environment variables configuration

## 🔧 Step 1: Google Cloud Console Setup

### 1.1 Create a New Project
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click "Select a project" → "New Project"
3. Name your project (e.g., "ResolveIt-OAuth")
4. Click "Create"

### 1.2 Enable Google+ API
1. In the Google Cloud Console, go to "APIs & Services" → "Library"
2. Search for "Google+ API" or "Google Identity"
3. Click on it and press "Enable"

### 1.3 Create OAuth 2.0 Credentials
1. Go to "APIs & Services" → "Credentials"
2. Click "Create Credentials" → "OAuth client ID"
3. Choose "Web application"
4. Name your OAuth client (e.g., "ResolveIt Web Client")

### 1.4 Configure Authorized URLs

#### For Development (Local):
```
Authorized JavaScript origins:
http://localhost:5000

Authorized redirect URIs:
http://localhost:5000/auth/google/callback
```

#### For Production:
```
Authorized JavaScript origins:
https://yourdomain.com
https://www.yourdomain.com

Authorized redirect URIs:
https://yourdomain.com/auth/google/callback
https://www.yourdomain.com/auth/google/callback
```

### 1.5 Get Your Credentials
After creating the OAuth client, you'll receive:
- **Client ID**: A long string starting with numbers and letters
- **Client Secret**: Another long string

## 🔐 Step 2: Environment Configuration

### 2.1 Local Development (.env file)
Create a `.env` file in your project root:
```env
# Google OAuth Configuration
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback

# Flask Configuration
FLASK_SECRET_KEY=your-secret-key-here
FLASK_ENV=development
```

### 2.2 Production Environment
Set these environment variables on your hosting platform:

#### For Heroku:
```bash
heroku config:set GOOGLE_CLIENT_ID=your_google_client_id_here
heroku config:set GOOGLE_CLIENT_SECRET=your_google_client_secret_here
heroku config:set GOOGLE_REDIRECT_URI=https://your-app.herokuapp.com/auth/google/callback
```

#### For Render:
```bash
# In your Render dashboard, go to Environment tab and add:
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
GOOGLE_REDIRECT_URI=https://your-app.onrender.com/auth/google/callback
```

#### For Vercel:
```bash
vercel env add GOOGLE_CLIENT_ID
vercel env add GOOGLE_CLIENT_SECRET
vercel env add GOOGLE_REDIRECT_URI
```

## 📦 Step 3: Install Dependencies

The required packages are already added to `requirements.txt`:
```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install google-auth==2.23.4
pip install google-auth-oauthlib==1.1.0
pip install google-auth-httplib2==0.1.1
pip install requests==2.31.0
```

## 🗄️ Step 4: Database Migration

The application automatically handles database migration. When you first run the app after adding OAuth support, it will:

1. Add new columns to the existing `users` table:
   - `google_id` (TEXT UNIQUE)
   - `profile_picture` (TEXT)
   - `auth_provider` (TEXT DEFAULT 'local')

2. Update existing users to have `auth_provider = 'local'`

## 🎨 Step 5: UI Features

### Google Sign-In Buttons
The application now includes:
- **Login Page**: "Continue with Google" button
- **Registration Page**: "Continue with Google" button
- **Modern Styling**: Google-branded buttons with hover effects
- **Dark Mode Support**: Optimized colors for both themes

### User Experience
- **Seamless Integration**: Users can sign in with Google or traditional email/password
- **Account Linking**: Existing users can link their Google accounts
- **Profile Pictures**: Google profile pictures are automatically imported
- **Secure Authentication**: Industry-standard OAuth 2.0 flow

## 🔒 Step 6: Security Considerations

### 6.1 Environment Variables
- Never commit OAuth credentials to version control
- Use environment variables for all sensitive data
- Rotate credentials regularly

### 6.2 HTTPS Requirements
- Google OAuth requires HTTPS in production
- Use SSL certificates for your domain
- Update redirect URIs to use HTTPS

### 6.3 Scope Permissions
The application requests minimal permissions:
- `openid`: Basic authentication
- `email`: User's email address
- `profile`: User's basic profile information

## 🧪 Step 7: Testing

### 7.1 Local Testing
1. Start your Flask application:
   ```bash
   python app.py
   ```

2. Navigate to `http://localhost:5000`

3. Try the "Continue with Google" button

4. Verify that:
   - Google OAuth flow works correctly
   - User data is saved to database
   - Login/logout functions properly

### 7.2 Production Testing
1. Deploy your application with environment variables
2. Test Google sign-in on production domain
3. Verify HTTPS redirect URIs work
4. Test account linking for existing users

## 🐛 Troubleshooting

### Common Issues

#### "Google authentication is not configured"
- Check that `GOOGLE_CLIENT_ID` environment variable is set
- Verify environment variables are loaded correctly

#### "Redirect URI mismatch"
- Ensure redirect URI in Google Console matches your environment
- Check for trailing slashes or HTTP vs HTTPS mismatches

#### "Invalid client" error
- Verify `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are correct
- Ensure OAuth client is enabled in Google Console

#### "Access blocked" error
- Check that your domain is authorized in Google Console
- Verify OAuth consent screen is configured

### Debug Mode
Enable debug logging in your Flask app:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📚 Additional Resources

- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [Flask-OAuthlib Documentation](https://flask-oauthlib.readthedocs.io/)
- [Google Cloud Console](https://console.cloud.google.com/)

## 🎉 Success!

Once configured, your ResolveIt application will support:
- ✅ Google OAuth sign-in and registration
- ✅ Traditional email/password authentication
- ✅ Account linking for existing users
- ✅ Profile picture import from Google
- ✅ Secure, industry-standard authentication
- ✅ Beautiful, responsive UI with dark mode support

Users can now choose their preferred authentication method, making your complaint management system more accessible and user-friendly!
