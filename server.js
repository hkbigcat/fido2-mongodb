require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const { isoBase64URL, generateUserID } = require('@simplewebauthn/server/helpers');

// Helper to convert id/publicKey from the library's WebAuthnCredential
// In some versions of @simplewebauthn/server, .id is already a base64url string
// while .publicKey is still Uint8Array. This helper is defensive.
function toBase64URL(input) {
  if (!input) return '';
  if (typeof input === 'string') return input; // already base64url (v10+ / v13 style)
  // Uint8Array, Buffer, ArrayBuffer, etc.
  try {
    if (input instanceof Uint8Array || Buffer.isBuffer(input)) {
      return isoBase64URL.fromBuffer(input);
    }
    if (input instanceof ArrayBuffer) {
      return isoBase64URL.fromBuffer(new Uint8Array(input));
    }
  } catch (e) {
    console.warn('toBase64URL conversion issue:', e.message);
  }
  return '';
}

// Config
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/fido2-demo';
const RP_NAME = process.env.RP_NAME || 'FIDO2 Demo';
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;

const app = express();

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'fido2-demo-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 1000 * 60 * 60 }, // 1 hour
  })
);

// MongoDB + Mongoose
mongoose
  .connect(MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// Schemas
const credentialSchema = new mongoose.Schema({
  credentialID: { type: String, required: true }, // base64url
  credentialPublicKey: { type: String, required: true }, // base64url
  counter: { type: Number, default: 0 },
  transports: { type: [String], default: [] },
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, lowercase: true },
  userID: { type: String, required: true }, // base64url or hex for WebAuthn user.id
  credentials: [credentialSchema],
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);

// Helpers
function getSessionUser(req) {
  return req.session.user || null;
}

function setSessionUser(req, user) {
  req.session.user = { id: user._id.toString(), username: user.username };
}

function clearSessionChallenge(req) {
  delete req.session.currentChallenge;
  delete req.session.challengeUsername;
}

// Routes

// Health
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', rpID: RP_ID, origin: ORIGIN });
});

// Get current session user (if any)
app.get('/api/me', (req, res) => {
  const user = getSessionUser(req);
  res.json({ user });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.json({ ok: true });
  });
});

// === REGISTRATION ===

// Start registration: generate options for navigator.credentials.create
app.post('/api/register/options', async (req, res) => {
  const { username } = req.body;
  if (!username || typeof username !== 'string' || username.length < 1) {
    return res.status(400).json({ error: 'Username is required' });
  }

  const cleanUsername = username.trim().toLowerCase();

  // Check if user exists
  let user = await User.findOne({ username: cleanUsername });

  if (user && user.credentials.length > 0) {
    // Allow adding another credential, but for basic demo we can still proceed (or error)
    // For simplicity, allow re-registering new passkey (adds to existing user)
  }

  // Create user if not exists
  if (!user) {
    const userIDBuffer = await generateUserID();
    const userID = isoBase64URL.fromBuffer(userIDBuffer);
    user = new User({
      username: cleanUsername,
      userID,
      credentials: [],
    });
    await user.save();
  }

  const existingCredentials = user.credentials.map((cred) => ({
    id: cred.credentialID,
    type: 'public-key',
    transports: cred.transports,
  }));

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: isoBase64URL.toBuffer(user.userID),
    userName: user.username,
    userDisplayName: username, // original casing for display
    attestationType: 'none', // 'direct' for more info, but none is simpler
    excludeCredentials: existingCredentials,
    authenticatorSelection: {
      residentKey: 'preferred', // allows discoverable if authenticator supports
      userVerification: 'preferred',
    },
    supportedAlgorithmIDs: [-7, -257], // ES256, RS256
  });

  // Store challenge in session for this registration
  req.session.currentChallenge = options.challenge;
  req.session.challengeUsername = user.username;

  res.json(options);
});

// Verify registration response from client
app.post('/api/register/verify', async (req, res) => {
  const { username, attestationResponse } = req.body;

  const expectedChallenge = req.session.currentChallenge;
  const sessionUsername = req.session.challengeUsername;

  if (!expectedChallenge || !sessionUsername) {
    return res.status(400).json({ error: 'No pending registration challenge' });
  }

  if (username && username.trim().toLowerCase() !== sessionUsername) {
    return res.status(400).json({ error: 'Username mismatch' });
  }

  const user = await User.findOne({ username: sessionUsername });
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: false,
    });

    const { verified, registrationInfo } = verification;

    if (!verified || !registrationInfo) {
      return res.status(400).json({ error: 'Registration verification failed' });
    }

    const { credential, credentialDeviceType, credentialBackedUp } = registrationInfo;

    // Save credential (store base64url strings)
    // Note: in @simplewebauthn/server v10+, credential.id is already a Base64URLString,
    // while publicKey remains Uint8Array. The toBase64URL helper handles both.
    const newCred = {
      credentialID: toBase64URL(credential.id),
      credentialPublicKey: toBase64URL(credential.publicKey),
      counter: credential.counter,
      transports: attestationResponse.response.transports || credential.transports || [],
    };

    if (!newCred.credentialID || !newCred.credentialPublicKey) {
      console.error('Invalid credential shape returned by verifyRegistrationResponse:', credential);
      return res.status(500).json({ error: 'Failed to extract credential data' });
    }

    // Avoid duplicate credentialID
    const exists = user.credentials.some((c) => c.credentialID === newCred.credentialID);
    if (!exists) {
      user.credentials.push(newCred);
      await user.save();
    }

    // Auto-login after successful registration
    setSessionUser(req, user);
    clearSessionChallenge(req);

    res.json({
      verified: true,
      user: { username: user.username },
      credentialID: newCred.credentialID,
    });
  } catch (err) {
    console.error('Registration verify error:', err);
    clearSessionChallenge(req);
    // Hide internal DB validation details from the user
    const msg = (err.message || '').includes('validation failed')
      ? 'Failed to store the passkey credential. Please try registering again.'
      : (err.message || 'Verification error');
    res.status(400).json({ error: msg });
  }
});

// === AUTHENTICATION / LOGIN ===

// Start login: generate options for navigator.credentials.get
app.post('/api/login/options', async (req, res) => {
  const { username } = req.body;
  if (!username || typeof username !== 'string') {
    return res.status(400).json({ error: 'Username is required' });
  }

  const cleanUsername = username.trim().toLowerCase();
  const user = await User.findOne({ username: cleanUsername });

  if (!user || user.credentials.length === 0) {
    return res.status(404).json({ error: 'User not found or no credentials registered' });
  }

  const allowCredentials = user.credentials.map((cred) => ({
    id: cred.credentialID, // base64url string is accepted by the lib
    type: 'public-key',
    transports: cred.transports,
  }));

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials,
    userVerification: 'preferred',
  });

  req.session.currentChallenge = options.challenge;
  req.session.challengeUsername = user.username;

  res.json(options);
});

// Verify authentication (login)
app.post('/api/login/verify', async (req, res) => {
  const { username, assertionResponse } = req.body;

  const expectedChallenge = req.session.currentChallenge;
  const sessionUsername = req.session.challengeUsername;

  if (!expectedChallenge || !sessionUsername) {
    return res.status(400).json({ error: 'No pending authentication challenge' });
  }

  if (username && username.trim().toLowerCase() !== sessionUsername) {
    return res.status(400).json({ error: 'Username mismatch' });
  }

  const user = await User.findOne({ username: sessionUsername });
  if (!user || user.credentials.length === 0) {
    clearSessionChallenge(req);
    return res.status(404).json({ error: 'User not found' });
  }

  // Find the matching credential
  const credentialID = assertionResponse.id; // base64url
  const dbCredential = user.credentials.find((c) => c.credentialID === credentialID);

  if (!dbCredential) {
    clearSessionChallenge(req);
    return res.status(400).json({ error: 'Credential not recognized for this user' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: dbCredential.credentialID,
        publicKey: isoBase64URL.toBuffer(dbCredential.credentialPublicKey),
        counter: dbCredential.counter,
        transports: dbCredential.transports,
      },
      requireUserVerification: false,
    });

    const { verified, authenticationInfo } = verification;

    if (!verified) {
      clearSessionChallenge(req);
      return res.status(400).json({ error: 'Authentication verification failed' });
    }

    // Update counter to prevent replay
    dbCredential.counter = authenticationInfo.newCounter;
    await user.save();

    // Login success
    setSessionUser(req, user);
    clearSessionChallenge(req);

    res.json({
      verified: true,
      user: { username: user.username },
    });
  } catch (err) {
    console.error('Login verify error:', err);
    clearSessionChallenge(req);
    res.status(400).json({ error: err.message || 'Verification error' });
  }
});

// List user's credentials (for demo UI)
app.get('/api/credentials', async (req, res) => {
  const sessUser = getSessionUser(req);
  if (!sessUser) return res.status(401).json({ error: 'Not logged in' });

  const user = await User.findById(sessUser.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({
    username: user.username,
    credentials: user.credentials.map((c) => ({
      credentialID: c.credentialID,
      counter: c.counter,
      transports: c.transports,
    })),
  });
});

// Delete a credential (nice for demo)
app.delete('/api/credentials/:credentialID', async (req, res) => {
  const sessUser = getSessionUser(req);
  if (!sessUser) return res.status(401).json({ error: 'Not logged in' });

  const { credentialID } = req.params;
  const user = await User.findById(sessUser.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.credentials = user.credentials.filter((c) => c.credentialID !== credentialID);
  await user.save();

  res.json({ ok: true, remaining: user.credentials.length });
});

// Fallback: serve index for unknown routes (SPA feel). Note: Express 5 requires named splat.
app.get('/*splat', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  res.sendFile('index.html', { root: 'public' });
});

app.listen(PORT, () => {
  console.log(`FIDO2 Demo server running on http://localhost:${PORT}`);
  console.log(`RP ID: ${RP_ID} | Origin: ${ORIGIN}`);
  console.log(`MongoDB: ${MONGO_URI}`);
});
