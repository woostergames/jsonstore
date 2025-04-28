require('dotenv').config();

const express = require('express');
const { google } = require('googleapis');
const multer = require('multer');
const cors = require('cors');
const { Readable } = require('stream');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const TOKEN_ROW_ID = 1;

const oauth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.env.REDIRECT_URI
);
const drive = google.drive({ version: 'v3', auth: oauth2Client });

const upload = multer({ storage: multer.memoryStorage() });

// Load the refresh token from Supabase
const loadRefreshToken = async () => {
  const { data, error } = await supabase
    .from('tokens')
    .select('refresh_token')
    .eq('id', TOKEN_ROW_ID)
    .single();

  if (error || !data?.refresh_token) {
    console.error('No refresh token found:', error);
    return;
  }

  oauth2Client.setCredentials({ refresh_token: data.refresh_token });
  console.log('🔑 Refresh token loaded from Supabase.');
};

// Save the refresh token to Supabase
const saveRefreshToken = async (tokens) => {
  if (!tokens.refresh_token) return;

  const { error } = await supabase
    .from('tokens')
    .upsert({ id: TOKEN_ROW_ID, refresh_token: tokens.refresh_token });

  if (error) {
    console.error('❌ Failed to save refresh token:', error);
  } else {
    console.log('✅ Refresh token saved to Supabase.');
  }
};

// Authentication route
app.get('/auth', (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: 'https://www.googleapis.com/auth/drive.file',
  });
  res.redirect(url);
});

// OAuth2 callback route
app.get('/oauth2callback', async (req, res) => {
  try {
    const { tokens } = await oauth2Client.getToken(req.query.code);
    oauth2Client.setCredentials(tokens);

    if (tokens.refresh_token) {
      await saveRefreshToken(tokens);
    }

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Authentication Successful</title>
        <style>
          body {
            background-color: #0f172a;
            color: #f8fafc;
            font-family: sans-serif;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            padding: 1rem;
          }
          h1 {
            font-size: 2.5rem;
            color: #22c55e;
            margin-bottom: 0.5rem;
          }
          p {
            font-size: 1.2rem;
            color: #94a3b8;
            max-width: 600px;
            text-align: center;
            margin-bottom: 2rem;
          }
          a {
            text-decoration: none;
            background-color: #3b82f6;
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-weight: bold;
            transition: background 0.3s ease;
          }
          a:hover {
            background-color: #2563eb;
          }
        </style>
      </head>
      <body>
        <h1>✅ Authentication Successful</h1>
        <p>Your Google account has been authenticated and the refresh token has been securely saved to Supabase. You can now upload files to your Google Drive.</p>
        <a href="/">Back to Home</a>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('OAuth2 callback error:', error);
    res.status(500).send('Authentication failed.');
  }
});

// Middleware to ensure the user is authenticated and refresh token is valid
const ensureAuth = async (req, res, next) => {
  try {
    // Load refresh token if it's not loaded already
    if (!oauth2Client.credentials.refresh_token) {
      await loadRefreshToken();
    }

    // If there's still no refresh token, authentication failed
    if (!oauth2Client.credentials.refresh_token) {
      return res.status(401).send('Not authenticated. Please visit /auth first.');
    }

    // Check if the access token has expired and refresh it
    const token = await oauth2Client.getAccessToken();
    if (!token.token || oauth2Client.isTokenExpiring()) {
      const newTokens = await oauth2Client.refreshAccessToken();
      oauth2Client.setCredentials(newTokens.credentials);
      await saveRefreshToken(newTokens.credentials);
      console.log('🔁 Token was refreshed automatically');
    }

    next();
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).send('Failed to refresh token.');
  }
};

// File upload endpoint
app.post('/upload', ensureAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');

  const fileMetadata = { name: req.body.name || req.file.originalname };
  const media = {
    mimeType: req.file.mimetype,
    body: Readable.from(req.file.buffer),
  };

  try {
    const file = await drive.files.create({
      resource: fileMetadata,
      media,
      fields: 'id',
    });
    res.send(`File uploaded successfully! File ID: ${file.data.id}`);
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).send('Error uploading file.');
  }
});

// Get public files from Google Drive
app.get('/public-files', ensureAuth, async (req, res) => {
  try {
    const response = await drive.files.list({
      q: 'trashed = false',
      fields: 'files(id, name)',
    });
    res.json(response.data.files);
  } catch (error) {
    console.error('Fetch error:', error);
    res.status(500).send('Error fetching files.');
  }
});

// Download a file from Google Drive
app.get('/download/:fileId', ensureAuth, async (req, res) => {
  const fileId = req.params.fileId;
  try {
    const response = await drive.files.get(
      { fileId, alt: 'media' },
      { responseType: 'stream' }
    );
    response.data.pipe(res);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).send('Error downloading file.');
  }
});

// Tokens info route
app.get('/tokens', (req, res) => {
  const creds = oauth2Client.credentials;
  res.json({
    access_token: creds.access_token,
    expiry_date: creds.expiry_date,
    refresh_token: creds.refresh_token ? '[HIDDEN]' : 'Not loaded',
    token_will_expire_in: creds.expiry_date
      ? `${Math.round((creds.expiry_date - Date.now()) / 1000)}s`
      : 'Unknown',
  });
});

// Debug refresh route
app.get('/debug-refresh', (req, res) => {
  const rt = oauth2Client.credentials.refresh_token;
  oauth2Client.setCredentials({ refresh_token: rt });
  res.send('🔧 Access token cleared. Try using /upload or /public-files to see if it refreshes.');
});

// Refresh token manually
app.get('/refreshtoken', async (req, res) => {
  try {
    if (!oauth2Client.credentials.refresh_token) {
      await loadRefreshToken();
    }

    if (!oauth2Client.credentials.refresh_token) {
      return res.status(401).send('Refresh token not found. Please authenticate first by visiting /auth.');
    }

    const tokens = await oauth2Client.refreshAccessToken();
    oauth2Client.setCredentials(tokens.credentials);
    await saveRefreshToken(tokens.credentials);

    res.send(`
      <h1>✅ Token Refreshed Successfully</h1>
      <p>Access token was successfully refreshed. New tokens are saved to Supabase.</p>
      <a href="/">Back to Home</a>
    `);
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).send(`
      <h1>❌ Failed to Refresh Token</h1>
      <p>An error occurred while trying to refresh the token. Please check the details below:</p>
      <pre>${error.message}</pre>
      <a href="/">Back to Home</a>
    `);
  }
});

// Home route
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Drive Upload App</title>
      <style>
        body {
          background-color: #0f172a;
          color: #e2e8f0;
          font-family: sans-serif;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 100vh;
          margin: 0;
        }
        h1 {
          font-size: 2.5rem;
          color: #38bdf8;
        }
        a {
          margin-top: 20px;
          text-decoration: none;
          color: white;
          background-color: #3b82f6;
          padding: 12px 24px;
          border-radius: 8px;
          font-weight: bold;
        }
        a:hover {
          background-color: #2563eb;
        }
      </style>
    </head>
    <body>
      <h1>🚀 Google Drive Uploader</h1>
      <a href="/auth">Click here to authenticate with Google Drive</a>
    </body>
    </html>
  `);
});

// Load the refresh token on startup
loadRefreshToken();

module.exports = app;
