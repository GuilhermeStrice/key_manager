// HTTP server and admin UI logic
import express from 'express';
import rateLimit from 'express-rate-limit';
import path from 'path';
import helmet from 'helmet'; // Security headers
import jwt from 'jsonwebtoken'; // Added for JWT
import cookieParser from 'cookie-parser'; // Added for cookie parsing
import session from 'express-session'; // For CSRF
import csrf from 'csurf'; // For CSRF
import crypto from 'crypto'; // For generating temporary session secret
import * as DataManager from '../lib/dataManager'; // Import DataManager functions
import { notifyClientStatusUpdate } from '../websocket/wsServer'; // Import notification function
import { getConfig, updateAutoApproveSetting } from '../lib/configManager'; // Import configManager functions

// This is a very basic way to hold the password for the session.
// In a more complex app, this would be handled more securely, perhaps not stored directly.
let serverAdminPasswordSingleton: string | null = null;

// Global flag for WebSocket auto-approval is now managed by configManager
// export let autoApproveWebSocketRegistrations: boolean = false;

// JWT_SECRET is now managed by configManager
// const JWT_SECRET = process.env.JWT_SECRET || 'DEFAULT_FALLBACK_SECRET_DO_NOT_USE_IN_PROD';
// if (JWT_SECRET === 'DEFAULT_FALLBACK_SECRET_DO_NOT_USE_IN_PROD' && getConfig().jwtSecret === 'DEFAULT_FALLBACK_SECRET_DO_NOT_USE_IN_PROD') {
    // Warning is handled by configManager
// }
const ADMIN_COOKIE_NAME = 'admin_token';


export function startHttpServer(port: number, serverAdminPassword?: string) {
  const app = express();

  // Use Helmet for basic security headers
  app.use(helmet());

  // Rate Limiting
  // General limiter for most admin routes
  const adminApiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    message: 'Too many requests from this IP, please try again after 15 minutes.',
  });

  // Stricter limiter for login attempts
  const loginLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // Limit each IP to 5 login attempts per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many login attempts from this IP, please try again after an hour.',
    skipSuccessfulRequests: true, // Do not count successful logins towards the limit
  });

  // Apply general limiter to all /admin routes, except login page GET
  // Specific routes like login POST will have their own stricter limiter.
  app.use('/admin', (req, res, next) => {
    // Skip general rate limiter for GET /admin/login to allow page rendering
    if (req.path === '/login' && req.method === 'GET') {
        return next();
    }
    adminApiLimiter(req, res, next);
  });


  // Setup EJS as the templating engine
  app.set('view engine', 'ejs');
  // Point Express to the `views` directory. __dirname is src/http, so ../../views
  app.set('views', path.join(__dirname, '../../views'));


  if (serverAdminPassword) {
    serverAdminPasswordSingleton = serverAdminPassword;
  }

  // Middleware for parsing URL-encoded data (for form submissions)
  app.use(express.urlencoded({ extended: true }));
  // Middleware for parsing JSON bodies
  app.use(express.json());
  // Middleware for parsing cookies
  app.use(cookieParser());

  // Session middleware configuration (needed for csurf)
  // IMPORTANT: Use a strong, unique secret from environment variables in production
  const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
  if (sessionSecret === crypto.randomBytes(32).toString('hex') && process.env.NODE_ENV !== 'test') { // Crude check if it's a temp secret
      console.warn('WARNING: Using a temporary session secret. Set SESSION_SECRET in your environment for production.');
  }
  app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: true, // Typically true for csurf if session is not otherwise established
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        httpOnly: true, // Helps prevent XSS
        sameSite: 'lax' // Good default for CSRF protection balance
    }
  }));

  // CSRF protection middleware
  // This should be after session and cookieParser
  // All non-GET requests to protected routes will need a CSRF token
  const csrfProtection = csrf({ cookie: false }); // Using session-based storage for CSRF secret
  // We will apply csrfProtection selectively or globally before routes that need it.
  // For admin panel, most POST routes will need it. Login POST might be an exception if handled before session.
  // For now, we will apply it to specific routes that render forms.
  // Note: The login page itself (GET /admin/login) does not need CSRF protection on its GET request,
  // as it doesn't contain forms that would be submitted with a CSRF token from *that* page load.
  // The POST /admin/login is also special as it establishes auth; CSRF is more for actions taken *after* auth.
  // However, if we decide to protect POST /admin/login, its GET handler would need to provide a token.
  // For now, focusing on authenticated admin actions.

  // Simple password protection for all /admin routes
  // TODO: Implement proper session-based authentication for the admin panel
  const adminAuth = (req: express.Request, res: express.Response, next: express.NextFunction): any => { // Added : any
    // Allow access to login page (GET and POST) without further checks here
    if (req.path === '/admin/login') {
        return next();
    }

    if (!serverAdminPasswordSingleton) {
        console.warn('Admin password not set for HTTP server. Admin routes will be inaccessible.');
        return res.status(500).send('Admin interface not configured.');
    }

    // 1. Check for JWT in cookie for all other /admin routes
    const tokenCookie = req.cookies[ADMIN_COOKIE_NAME];
    if (tokenCookie) {
        try {
            jwt.verify(tokenCookie, getConfig().jwtSecret); // Throws error if invalid
            // Optional: req.user = decoded;
            return next(); // Valid JWT cookie, allow access
        } catch (err: any) { // Type err as any to allow accessing err.message
            // console.warn is kept as it's useful for ops, but detailed trace logs removed
            console.warn('Invalid JWT cookie:', err.message);
            res.clearCookie(ADMIN_COOKIE_NAME, { path: '/admin' }); // Clear bad cookie
            return res.status(401).redirect('/admin/login'); // Redirect immediately
        }
    }

    // Bearer token functionality removed. Authentication is cookie-based.
    // const authHeader = req.headers.authorization;
    // if (authHeader && authHeader.startsWith('Bearer ')) {
    //     const bearerToken = authHeader.substring(7);
    //     if (bearerToken === serverAdminPasswordSingleton) {
    //         return next();
    //     }
    // }

    // If here, no valid JWT cookie was found (or an invalid one was cleared),
    // so redirect to login page.
    return res.status(401).redirect('/admin/login');
  };

  // The adminAuth middleware is applied individually to each protected /admin/* route below,
  // except for /admin/login routes themselves which handle their own logic.

  // Apply auth to all /admin routes except potentially the login page itself if handled differently
  // app.use('/admin', adminAuth); // This would protect /admin/login too, needs care.
  // Let's make specific routes and protect them individually or use a more granular approach.

  app.get('/admin/login', (req, res) => {
    // This route is now effectively handled by the adminAuth logic if not authenticated
    // but we can provide the form directly if accessed via GET.
     res.send(`
        <h1>Admin Login</h1>
        <form action="/admin/login" method="POST">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Login</button>
        </form>
        <p>Hint: Use the server startup password.</p>
    `);
  });

  app.post('/admin/login', loginLimiter, express.urlencoded({ extended: false }), (req, res) => {
     if (req.body.password && req.body.password === serverAdminPasswordSingleton) {
        // Generate JWT
        const token = jwt.sign({ admin: true, user: 'admin' }, getConfig().jwtSecret, { expiresIn: '1h' });
        // Set cookie options: httpOnly for security, secure in production, path for admin routes
        const cookieOptions: express.CookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            path: '/admin',
            sameSite: 'lax' // Recommended for CSRF protection
        };
        res.cookie(ADMIN_COOKIE_NAME, token, cookieOptions);
        res.redirect('/admin'); // Redirect to admin page
    } else {
        res.status(401).send('Login failed. <a href="/admin/login">Try again</a>');
    }
  });


  // Protected admin route
  app.get('/admin', adminAuth, csrfProtection, async (req, res) => { // Added csrfProtection
    try {
      const allKeys = DataManager.getAllSecretKeys(); // Updated function name
      const secrets = allKeys.map(key => ({
        key,
        value: DataManager.getSecretItem(key) // Updated function name
      }));
      // The 'password' variable was passed to EJS for link construction.
      const message = req.query.message ? { text: req.query.message.toString(), type: req.query.messageType?.toString() || 'info' } : null;

      res.render('admin', {
        secrets,
        password: '', // EJS links will be updated to not use this
        message,
        editingItemKey: null,
        itemToEdit: null,
        csrfToken: req.csrfToken() // Pass CSRF token to template
      });
    } catch (error) {
      console.error("Error rendering admin page:", error);
      res.status(500).send("Error loading admin page.");
    }
  });

  // Route to show edit form
  app.get('/admin/edit-secret/:key', adminAuth, csrfProtection, async (req, res) => { // Added csrfProtection
    try {
        const itemKey = decodeURIComponent(req.params.key);
        const itemToEdit = DataManager.getSecretItem(itemKey); // Updated function name
        // Password from query is no longer used. Auth is via Bearer token.

        if (itemToEdit === undefined) {
            // No currentPassword to pass in redirect
            res.redirect(`/admin?message=Secret+not+found&messageType=error`);
            return;
        }

        const allKeys = DataManager.getAllSecretKeys(); // Updated function name
        const secrets = allKeys.map(key => ({ key, value: DataManager.getSecretItem(key) })); // Updated function name

        res.render('admin', {
            secrets,
            password: '', // EJS links will be updated
            message: null,
            editingItemKey: itemKey,
            itemToEdit: itemToEdit,
            csrfToken: req.csrfToken() // Pass CSRF token to template
        });
    } catch (error) {
        console.error("Error rendering edit page:", error);
        // No currentPassword to pass in redirect
        res.redirect(`/admin?message=Error+loading+edit+page&messageType=error`);
    }
  });

  // Handle Add Secret
  app.post('/admin/add-secret', adminAuth, csrfProtection, async (req, res) => { // Added csrfProtection
    const { secretKey, secretValue } = req.body;
    // currentPassword from query is removed. Bearer token handles auth.
    let parsedValue = secretValue;
    try {
        const trimmedValue = secretValue.trim();
        if ((trimmedValue.startsWith('{') && trimmedValue.endsWith('}')) || (trimmedValue.startsWith('[') && trimmedValue.endsWith(']'))) {
            parsedValue = JSON.parse(trimmedValue);
        }
    } catch (e) { /* Not valid JSON, store as string */ }

    try {
      if (!secretKey || typeof secretValue === 'undefined') {
        throw new Error('Secret key and value are required.');
      }
      if (DataManager.getSecretItem(secretKey) !== undefined) { // Updated function name
        throw new Error('Secret key already exists. Use edit to modify.');
      }
      await DataManager.setSecretItem(secretKey, parsedValue); // Updated function name
      res.redirect(`/admin?message=Secret+added&messageType=success`);
    } catch (error: any) {
      console.error("Error adding secret:", error);
      res.redirect(`/admin?message=Error+adding+secret:+${encodeURIComponent(error.message)}&messageType=error`);
    }
  });

  // Handle Update Secret
  app.post('/admin/update-secret', adminAuth, csrfProtection, async (req, res) => { // Added csrfProtection
    const { originalKey, secretKey, secretValue } = req.body;
    // currentPassword from query is removed. Bearer token handles auth.
    let parsedValue = secretValue;
    try {
        const trimmedValue = secretValue.trim();
        if ((trimmedValue.startsWith('{') && trimmedValue.endsWith('}')) || (trimmedValue.startsWith('[') && trimmedValue.endsWith(']'))) {
            parsedValue = JSON.parse(trimmedValue);
        }
    } catch (e) { /* Store as string if not valid JSON */ }

    try {
        if (!originalKey || !secretKey || typeof secretValue === 'undefined') {
            throw new Error('Original key, new key, and value are required.');
        }
        if (originalKey !== secretKey) {
            if (DataManager.getSecretItem(secretKey) !== undefined) { // Corrected: getSecretItem
                 throw new Error(`New key "${secretKey}" already exists. Choose a different key.`);
            }
            await DataManager.deleteSecretItem(originalKey); // Corrected: deleteSecretItem
            await DataManager.setSecretItem(secretKey, parsedValue); // Corrected: setSecretItem
        } else {
            await DataManager.setSecretItem(originalKey, parsedValue); // Corrected: setSecretItem
        }
        res.redirect(`/admin?message=Secret+updated&messageType=success`);
    } catch (error: any) {
        console.error("Error updating secret:", error);
        res.redirect(`/admin/edit-secret/${encodeURIComponent(originalKey)}?message=Error+updating+secret:+${encodeURIComponent(error.message)}&messageType=error`);
    }
  });

  // Handle Delete Secret
  app.post('/admin/delete-secret/:key', adminAuth, csrfProtection, async (req, res) => { // Added csrfProtection
    const itemKey = decodeURIComponent(req.params.key);
    // currentPassword from query is removed. Bearer token handles auth.
    try {
      await DataManager.deleteSecretItem(itemKey); // Corrected: deleteSecretItem
      res.redirect(`/admin?message=Secret+deleted&messageType=success`);
    } catch (error: any) {
      console.error("Error deleting secret:", error);
      res.redirect(`/admin?message=Error+deleting+secret:+${encodeURIComponent(error.message)}&messageType=error`);
    }
  });

  // --- WebSocket Auto-Approval Setting Routes ---
  app.get('/admin/settings/auto-approve-ws-status', adminAuth, (req, res) => {
    // This route might still be useful for other API consumers, so it uses getConfig()
    res.json({ autoApproveEnabled: getConfig().autoApproveWebSocketRegistrations });
  });

  app.post('/admin/settings/toggle-auto-approve-ws', adminAuth, csrfProtection, (req, res) => { // Added csrfProtection
    // If checkbox is checked, req.body.autoApproveWs will be 'on' (or its 'value' attribute if set).
    // If unchecked, autoApproveWs will not be in req.body.
    const newAutoApproveState = !!req.body.autoApproveWs;
    updateAutoApproveSetting(newAutoApproveState); // Update and save config
    console.log(`WebSocket auto-approval toggled to: ${newAutoApproveState}`);
    // Instead of JSON, redirect back to the clients page
    res.redirect('/admin/clients?message=WebSocket+auto-approval+setting+updated&messageType=success');
  });

  // --- Client Management Routes ---

  // Note: GET routes for clients already have csrfProtection for token generation
  app.get('/admin/clients', adminAuth, csrfProtection, async (req, res) => {
    try {
      const pendingClients = DataManager.getPendingClients();
      const approvedClients = DataManager.getApprovedClients();
      // currentPassword from query is removed.
      const message = req.query.message ? { text: req.query.message.toString(), type: req.query.messageType?.toString() || 'info' } : null;

      res.render('clients', {
        pendingClients,
        approvedClients,
        password: '', // EJS links will be updated
        message,
        managingClientSecrets: null, // Not managing specific client secrets by default
        autoApproveWsEnabled: getConfig().autoApproveWebSocketRegistrations, // Pass current state to template
        csrfToken: req.csrfToken() // Pass CSRF token to template
      });
    } catch (error) {
      console.error("Error rendering clients page:", error);
      res.status(500).send("Error loading client management page.");
    }
  });

  app.post('/admin/clients/approve/:clientId', adminAuth, csrfProtection, async (req, res) => { // Added csrfProtection
    const { clientId } = req.params;
    // currentPassword from query is removed.
    try {
      const client = await DataManager.approveClient(clientId);
      // authToken is no longer generated or part of ClientInfo
      notifyClientStatusUpdate(clientId, 'approved', `Client ${client.name} has been approved by an administrator.`);
      res.redirect(`/admin/clients?message=Client+${client.name}+approved.&messageType=success`);
    } catch (error: any) {
      res.redirect(`/admin/clients?message=Error+approving+client:+${encodeURIComponent(error.message)}&messageType=error`);
    }
  });

  app.post('/admin/clients/reject/:clientId', adminAuth, csrfProtection, async (req, res) => { // Added csrfProtection
    const { clientId } = req.params;
    // currentPassword from query is removed.
    try {
      const client = await DataManager.rejectClient(clientId);
      notifyClientStatusUpdate(clientId, 'rejected', `Client ${client.name} has been rejected by an administrator.`);
      res.redirect(`/admin/clients?message=Client+${client.name}+rejected.&messageType=success`);
    } catch (error: any) {
      res.redirect(`/admin/clients?message=Error+rejecting+client:+${encodeURIComponent(error.message)}&messageType=error`);
    }
  });

  app.post('/admin/clients/revoke/:clientId', adminAuth, csrfProtection, async (req, res) => { // Added csrfProtection
    const { clientId } = req.params;
    // currentPassword from query is removed.
    try {
      // Revoking means deleting the client in this implementation
      await DataManager.deleteClient(clientId);
      res.redirect(`/admin/clients?message=Client+${clientId}+revoked+(deleted).&messageType=success`);
    } catch (error: any) {
      res.redirect(`/admin/clients?message=Error+revoking+client:+${encodeURIComponent(error.message)}&messageType=error`);
    }
  });

  app.get('/admin/clients/:clientId/secrets', adminAuth, csrfProtection, async (req, res) => { // Added csrfProtection
    const { clientId } = req.params;
    // currentPassword from query is removed.
    try {
      const client = DataManager.getClient(clientId);
      if (!client || client.status !== 'approved') {
        res.redirect(`/admin/clients?message=Client+not+found+or+not+approved.&messageType=error`);
        return;
      }
      const allSecretKeys = DataManager.getAllSecretKeys();
      const message = req.query.message ? { text: req.query.message.toString(), type: req.query.messageType?.toString() || 'info' } : null;

      // Render the same clients.ejs but with a special state for managing one client's secrets
      res.render('clients', {
        pendingClients: [], // Not needed for this view part
        approvedClients: [], // Not needed for this view part
        password: '', // EJS links will be updated
        message,
        managingClientSecrets: {
          client: client,
          allSecrets: allSecretKeys
        },
        csrfToken: req.csrfToken() // Pass CSRF token to template
      });
    } catch (error: any) {
      res.redirect(`/admin/clients?message=Error+loading+secret+management+for+client:+${encodeURIComponent(error.message)}&messageType=error`);
    }
  });

  app.post('/admin/clients/:clientId/secrets/update', adminAuth, csrfProtection, async (req, res) => { // Added csrfProtection to POST route
    const { clientId } = req.params;
    let { associatedSecretKeys } = req.body; // This will be an array or single string if only one selected
    // currentPassword from query is removed.

    if (!Array.isArray(associatedSecretKeys)) {
        associatedSecretKeys = associatedSecretKeys ? [associatedSecretKeys] : [];
    }

    try {
      const client = DataManager.getClient(clientId);
      if (!client || client.status !== 'approved') {
        throw new Error("Client not found or not approved.");
      }

      // Get all currently available secret keys to validate against
      const allValidSecretKeys = DataManager.getAllSecretKeys();
      const validKeysToAssociate = associatedSecretKeys.filter((key: string) => allValidSecretKeys.includes(key));

      // Update client's associated keys: first clear existing, then add selected ones.
      // A more efficient way might be to find differences, but this is straightforward.
      client.associatedSecretKeys = []; // Clear current associations
      for (const secretKey of validKeysToAssociate) {
          // The DataManager.associateSecretWithClient is additive and checks for duplicates.
          // We are rebuilding the list here directly on the client object before a single save.
          // This is a conceptual simplification. For robustness, one might call associate for each.
          // Let's refine this to call DataManager for each association for consistency with its design.
          // However, the current DataManager.associateSecretWithClient saves on each call.
          // For multiple updates, it's better to have a function like `setClientAssociatedSecrets`.
          // Lacking that, we'll update the client object directly and save once. This means
          // the `associateSecretWithClient` and `dissociateSecretFromClient` might be more for single operations.
          // Let's assume we'll update the client object directly and then save.
      }
      client.associatedSecretKeys = validKeysToAssociate; // Directly set the new list
      client.dateUpdated = new Date().toISOString();
      // Need a function in DataManager to update a client object or save the whole store.
      // `DataManager.setItem` is for secrets. Let's add a `updateClient` function to DataManager.
      // For now, we'll rely on the fact that `client` is a reference from `dataStore.clients[clientId]`
      // and `saveData` will persist it. This is risky if getClient returns a copy.
      // Corrected approach: getClient returns a copy, so we need an updateClient function.
      // I will add a placeholder for such a function and then implement it in DataManager.

      // This is a temporary direct modification before adding updateClient
      // dataStore.clients[client.id] = client; // This won't work if getClient returns a deep copy
      // await DataManager.saveData(); // This would save the whole store
      // The above is incorrect because getClient returns a deep copy.
      // Proper way: fetch original client, modify, then use a new update function.

      // Let's use existing associate/dissociate for now, though less efficient for bulk.
      const originalClientData = DataManager.getClient(clientId); // Fetch original again
      if (!originalClientData) throw new Error("Client disappeared");

      const keysToAdd = validKeysToAssociate.filter((key:string) => !originalClientData.associatedSecretKeys.includes(key));
      const keysToRemove = originalClientData.associatedSecretKeys.filter((key:string) => !validKeysToAssociate.includes(key));

      for (const key of keysToAdd) {
        await DataManager.associateSecretWithClient(clientId, key);
      }
      for (const key of keysToRemove) {
        await DataManager.dissociateSecretFromClient(clientId, key);
      }

      res.redirect(`/admin/clients/${clientId}/secrets?message=Client+secret+associations+updated.&messageType=success`);
    } catch (error: any) {
      res.redirect(`/admin/clients/${clientId}/secrets?message=Error+updating+associations:+${encodeURIComponent(error.message)}&messageType=error`);
    }
  });


  app.get('/admin/logout', (req, res) => { // adminAuth not strictly needed if just clearing cookie
    res.clearCookie(ADMIN_COOKIE_NAME, { path: '/admin' });
    res.redirect('/admin/login');
  });

  // Placeholder for other non-admin routes or a root welcome
  app.get('/', (req, res) => {
    res.send('<h1>Key/Info Manager</h1><p>This is the public-facing part of the server (if any).</p><p><a href="/admin/login">Admin Login</a></p>');
  });

  const server = app.listen(port, () => {
    console.log(`HTTP server started on http://localhost:${port}`);
    if (!serverAdminPasswordSingleton) {
        console.warn("HTTP Server started without an admin password. Admin panel will be inaccessible.");
    } else {
        console.log("Admin panel access requires the server startup password.");
    }
  });

  // CSRF Error Handler
  // This must be defined as an error-handling middleware (with 4 arguments)
  // and should be placed after all other middleware and routes.
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (err.code === 'EBADCSRFTOKEN') {
      console.warn(`CSRF token validation failed for request: ${req.method} ${req.path}`);
      // Send a user-friendly error page or a simple 403 response
      res.status(403).send('Invalid CSRF token. Please refresh the page and try again, or ensure cookies are enabled.');
    } else {
      // If it's not a CSRF error, pass it to the next error handler (if any)
      // or let Express handle it as a generic server error.
      console.error("Unhandled error:", err); // Log other errors for debugging
      next(err);
    }
  });

  // It's important that the CSRF error handler is added before any generic
  // error handler that might catch all errors and send a 500 response without
  // checking the error type. If no other generic error handler exists, this is fine.

  return server; // Return the Node.js HTTP server instance
}
