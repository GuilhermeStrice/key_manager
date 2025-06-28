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
import {
    createSecretGroup,
    getAllSecretGroups,
    getSecretGroupById,
    renameSecretGroup,
    deleteSecretGroup,
    createSecretInGroup,
    updateSecretValue,
    deleteSecret,
    getSecretWithValue
} from '../lib/dataManager'; // Specific imports for Phase 1
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

  // Middleware for serving static files (e.g., CSS, client-side JS)
  // __dirname is src/http, so ../../public points to the project's public directory
  app.use(express.static(path.join(__dirname, '../../public')));

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

  // UI: Handle deleting a secret from within a group view
  app.post('/admin/groups/:groupId/secrets/:secretKey/delete', adminAuth, csrfProtection, async (req, res) => {
    const groupId = parseInt(req.params.groupId, 10); // For redirect
    const secretKey = decodeURIComponent(req.params.secretKey);
    try {
        if (isNaN(groupId)) throw new Error('Invalid group ID for redirect.'); // Should not happen if reached here from valid page

        await deleteSecret(secretKey); // deleteSecret handles removing from group and secrets list
        res.redirect(`/admin/groups/${groupId}/secrets?message=Secret+deleted+successfully.&messageType=success`);
    } catch (error: any) {
        console.error(`Error deleting secret ${secretKey} from group context ${groupId}:`, error);
        res.redirect(`/admin/groups/${groupId}/secrets?message=Error+deleting+secret.+Please+check+server+logs.&messageType=error`);
    }
  });

  // UI: Show form to edit a secret's value within a group
  app.get('/admin/groups/:groupId/secrets/:secretKey/edit', adminAuth, csrfProtection, async (req, res) => {
    const groupId = parseInt(req.params.groupId, 10);
    const secretKey = decodeURIComponent(req.params.secretKey); // secretKey might have URL encoded chars

    try {
        if (isNaN(groupId)) throw new Error('Invalid group ID.');

        const group = getSecretGroupById(groupId);
        if (!group) throw new Error('Group not found.');
        if (!group.keys.includes(secretKey)) throw new Error('Secret not found in this group.');

        const secretToEdit = getSecretWithValue(secretKey);
        if (!secretToEdit) throw new Error('Secret details not found.');

        // Re-fetch other necessary data for rendering group_secrets.ejs
        const secretsInGroup = group.keys.map(key => {
            const secretData = getSecretWithValue(key);
            return { key, value: secretData?.value };
        }).filter(s => s.value !== undefined);

        res.render('group_secrets', {
            group,
            secretsInGroup,
            message: null, // Or pass from query if needed
            csrfToken: req.csrfToken(),
            editingSecretKey: secretKey,
            secretToEdit: secretToEdit.value
        });

    } catch (error: any) {
        console.error(`Error preparing to edit secret ${secretKey} in group ${groupId}:`, error);
        res.redirect(`/admin/groups/${groupId}/secrets?message=Error+loading+secret+for+edit.+Please+check+server+logs.&messageType=error`);
    }
  });

  // UI: Handle updating a secret's value within a group
  app.post('/admin/groups/:groupId/secrets/:secretKey/update', adminAuth, csrfProtection, async (req, res) => {
    const groupId = parseInt(req.params.groupId, 10);
    const secretKey = decodeURIComponent(req.params.secretKey);
    try {
        if (isNaN(groupId)) throw new Error('Invalid group ID.');

        const { secretValue } = req.body;
        if (secretValue === undefined) {
            throw new Error('Secret value is required.');
        }

        // Optional: Verify secret still belongs to this group before updating if desired, though updateSecretValue only cares about the key.
        // const currentSecret = getSecretWithValue(secretKey);
        // if (!currentSecret || currentSecret.groupId !== groupId) {
        //     throw new Error('Secret not found in this group or group association mismatch.');
        // }

        let parsedValue = secretValue;
        try {
            const trimmedValue = typeof secretValue === 'string' ? secretValue.trim() : secretValue;
            if (typeof trimmedValue === 'string' && ((trimmedValue.startsWith('{') && trimmedValue.endsWith('}')) || (trimmedValue.startsWith('[') && trimmedValue.endsWith(']')))) {
                parsedValue = JSON.parse(trimmedValue);
            }
        } catch (e) { /* Not valid JSON, store as string */ }

        await updateSecretValue(secretKey, parsedValue);
        res.redirect(`/admin/groups/${groupId}/secrets?message=Secret+value+updated+successfully.&messageType=success`);
    } catch (error: any) {
        console.error(`Error updating secret ${secretKey} in group ${groupId}:`, error);
        res.redirect(`/admin/groups/${groupId}/secrets/${encodeURIComponent(secretKey)}/edit?message=Error+updating+secret.+Please+check+server+logs.&messageType=error`);
    }
  });

  // UI: Handle adding a new secret to a specific group
  app.post('/admin/groups/:groupId/secrets/add', adminAuth, csrfProtection, async (req, res) => {
    const groupId = parseInt(req.params.groupId, 10);
    try {
        if (isNaN(groupId)) {
            throw new Error('Invalid group ID.');
        }
        const { secretKey, secretValue } = req.body;
        if (!secretKey || typeof secretKey !== 'string' || secretKey.trim() === "" || secretValue === undefined) {
            throw new Error('Secret key (non-empty string) and value are required.');
        }
        // Attempt to parse JSON if applicable, similar to add-secret logic
        let parsedValue = secretValue;
        try {
            const trimmedValue = typeof secretValue === 'string' ? secretValue.trim() : secretValue;
            if (typeof trimmedValue === 'string' && ((trimmedValue.startsWith('{') && trimmedValue.endsWith('}')) || (trimmedValue.startsWith('[') && trimmedValue.endsWith(']')))) {
                parsedValue = JSON.parse(trimmedValue);
            }
        } catch (e) { /* Not valid JSON, store as string if it was a string */ }


        await createSecretInGroup(groupId, secretKey.trim(), parsedValue);
        res.redirect(`/admin/groups/${groupId}/secrets?message=Secret+added+to+group+successfully.&messageType=success`);
    } catch (error: any) {
        console.error(`Error adding secret to group ${groupId}:`, error);
        let userMessage = "Error+adding+secret+to+group.+Please+check+server+logs.";
        if (error.message && error.message.includes("already exists")) {
            userMessage = "Error+adding+secret+to+group:+A+secret+with+that+key+already+exists.";
        }
        res.redirect(`/admin/groups/${groupId}/secrets?message=${userMessage}&messageType=error`);
    }
  });

  // UI: View/Manage secrets within a specific group
  app.get('/admin/groups/:groupId/secrets', adminAuth, csrfProtection, async (req, res) => {
    try {
        const groupId = parseInt(req.params.groupId, 10);
        if (isNaN(groupId)) {
            return res.redirect('/admin?message=Invalid+group+ID+format.&messageType=error');
        }

        const group = getSecretGroupById(groupId);
        if (!group) {
            return res.redirect('/admin?message=Group+not+found.&messageType=error');
        }

        const secretsInGroup = group.keys.map(key => {
            const secretData = getSecretWithValue(key);
            return {
                key,
                value: secretData?.value, // Value might be undefined if data is inconsistent
                // groupId is known to be 'group.id' for these secrets
            };
        }).filter(s => s.value !== undefined); // Filter out any inconsistencies if secret value couldn't be fetched

        const message = req.query.message ? { text: req.query.message as string, type: req.query.messageType as string || 'info' } : null;

        // For now, rendering a new EJS view. Could also be a modified admin.ejs
        res.render('group_secrets', {
            group,
            secretsInGroup,
            message,
            csrfToken: req.csrfToken(),
            editingSecretKey: null, // For edit secret form later
            secretToEdit: null    // For edit secret form later
        });

    } catch (error: any) {
        console.error(`Error viewing secrets for group ${req.params.groupId}:`, error);
        res.redirect(`/admin?message=Error+loading+secrets+for+group.+Please+check+server+logs.&messageType=error`);
    }
  });

  // UI: Handle the form submission for deleting a group
  app.post('/admin/groups/delete/:groupId', adminAuth, csrfProtection, async (req, res) => {
    try {
        const groupId = parseInt(req.params.groupId, 10);
        if (isNaN(groupId)) {
            throw new Error('Invalid group ID.');
        }
        await deleteSecretGroup(groupId);
        res.redirect('/admin?message=Group+and+its+secrets+deleted+successfully.&messageType=success');
    } catch (error: any) {
        console.error("Error deleting secret group:", error);
        res.redirect(`/admin?message=Error+deleting+group.+Please+check+server+logs.&messageType=error`);
    }
  });

  // UI: Show form to edit/rename a group
  app.get('/admin/groups/edit/:groupId', adminAuth, csrfProtection, async (req, res) => {
    try {
        const groupId = parseInt(req.params.groupId, 10);
        if (isNaN(groupId)) {
            return res.redirect('/admin?message=Invalid+group+ID.&messageType=error');
        }
        const groupToEdit = getSecretGroupById(groupId);
        if (!groupToEdit) {
            return res.redirect('/admin?message=Group+not+found.&messageType=error');
        }

        // Render the main admin page, but provide data to show the edit group form
        const allSecretKeysList = DataManager.getAllSecretKeys();
        const secretsWithValueAndGroup = allSecretKeysList.map(key => {
            const secretData = DataManager.getSecretWithValue(key);
            return { key, value: secretData?.value, groupId: secretData?.groupId };
        });
        const allGroups = getAllSecretGroups();
        const message = req.query.message ? { text: req.query.message as string, type: req.query.messageType as string || 'info' } : null;

        res.render('admin', {
            secrets: secretsWithValueAndGroup,
            secretGroups: allGroups,
            editingGroup: groupToEdit, // Pass the group to be edited
            message,
            editingItemKey: null, // Not editing a secret key here
            itemToEdit: null,     // Not editing a secret key value here
            csrfToken: req.csrfToken()
        });
    } catch (error: any) {
        console.error("Error preparing to edit group:", error);
        res.redirect(`/admin?message=Error+loading+group+for+edit.+Please+check+server+logs.&messageType=error`);
    }
  });

  // UI: Handle the form submission for renaming a group
  app.post('/admin/groups/rename/:groupId', adminAuth, csrfProtection, async (req, res) => {
    try {
        const groupId = parseInt(req.params.groupId, 10);
        const { newGroupName } = req.body;

        if (isNaN(groupId)) {
            throw new Error('Invalid group ID.');
        }
        if (!newGroupName || typeof newGroupName !== 'string' || newGroupName.trim() === "") {
            throw new Error('New group name must be a non-empty string.');
        }
        await renameSecretGroup(groupId, newGroupName.trim());
        res.redirect('/admin?message=Group+renamed+successfully.&messageType=success');
    } catch (error: any) {
        console.error("Error renaming secret group:", error);
        const groupIdParam = req.params.groupId || '';
        const redirectPath = groupIdParam ? `/admin/groups/edit/${groupIdParam}` : '/admin';
        let userMessage = "Error+renaming+group.+Please+check+server+logs.";
        if (error.message && error.message.includes("already exists")) {
            userMessage = "A+group+with+that+name+already+exists.";
        } else if (error.message && error.message.includes("not found")) {
            userMessage = "Group+not+found+and+could+not+be+renamed.";
        }
        res.redirect(`${redirectPath}?message=${userMessage}&messageType=error`);
    }
  });


  // Protected admin route
  app.get('/admin', adminAuth, csrfProtection, async (req, res) => { // Added csrfProtection
    try {
      const allSecretKeysList = DataManager.getAllSecretKeys(); // Get all keys
      const secretsWithValueAndGroup = allSecretKeysList.map(key => {
        const secretData = DataManager.getSecretWithValue(key); // Get { value, groupId }
        return {
          key,
          value: secretData ? secretData.value : undefined, // Handle case where secret might be gone if data is inconsistent
          groupId: secretData ? secretData.groupId : undefined
        };
      });

      const secretGroups = DataManager.getAllSecretGroups(); // Fetch all secret groups

      const message = req.query.message ? { text: req.query.message.toString(), type: req.query.messageType?.toString() || 'info' } : null;

      res.render('admin', {
        secrets: secretsWithValueAndGroup, // Now includes groupId
        secretGroups, // Pass groups to the template
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
        const secretData = DataManager.getSecretWithValue(itemKey); // Get { value, groupId }

        if (!secretData) {
            return res.redirect(`/admin?message=Secret+"${itemKey}"+not+found&messageType=error`);
        }

        let groupName = 'N/A (Orphaned or Error)';
        if (secretData.groupId) {
            const group = DataManager.getSecretGroupById(secretData.groupId);
            if (group) {
                groupName = group.name;
            } else {
                console.warn(`Secret "${itemKey}" has groupId ${secretData.groupId}, but group was not found.`);
            }
        } else {
            console.warn(`Secret "${itemKey}" does not have a groupId. This indicates data inconsistency.`);
        }

        const itemToEditDetails = {
            value: secretData.value,
            groupId: secretData.groupId,
            groupName: groupName
        };

        // Data for the main admin page (lists of secrets and groups)
        const allSecretKeysList = DataManager.getAllSecretKeys();
        const secretsWithValueAndGroup = allSecretKeysList.map(key => {
            const sData = DataManager.getSecretWithValue(key);
            return { key, value: sData?.value, groupId: sData?.groupId };
        });
        const allGroups = DataManager.getAllSecretGroups();

        res.render('admin', {
            secrets: secretsWithValueAndGroup,
            secretGroups: allGroups,
            password: '',
            message: null,
            editingItemKey: itemKey,
            itemToEdit: itemToEditDetails, // Pass new structure
            csrfToken: req.csrfToken()
        });
    } catch (error: any) {
        console.error("Error rendering edit page:", error);
        res.redirect(`/admin?message=Error+loading+edit+page.+Please+check+server+logs.&messageType=error`);
    }
  });

  // Handle Add Secret
  app.post('/admin/add-secret', adminAuth, csrfProtection, async (req, res) => { // Added csrfProtection
    const { groupId, secretKey, secretValue } = req.body; // Added groupId
    // currentPassword from query is removed. Bearer token handles auth.

    const numGroupId = parseInt(groupId, 10);
    if (isNaN(numGroupId)) {
        return res.redirect(`/admin?message=Error+adding+secret:+Invalid+group+ID.&messageType=error`);
    }

    let parsedValue = secretValue;
    try {
        const trimmedValue = secretValue.trim();
        if ((trimmedValue.startsWith('{') && trimmedValue.endsWith('}')) || (trimmedValue.startsWith('[') && trimmedValue.endsWith(']'))) {
            parsedValue = JSON.parse(trimmedValue);
        }
    } catch (e) { /* Not valid JSON, store as string */ }

    try {
      // Validation for secretKey and secretValue now happens within createSecretInGroup or earlier.
      // createSecretInGroup will also check for key uniqueness.
      // The main check here was for required fields, which is good.
      if (!secretKey || typeof secretValue === 'undefined' || !groupId) { // Added groupId check
        throw new Error('Group ID, secret key, and value are required.');
      }
      // Deprecated: DataManager.setSecretItem(secretKey, parsedValue);
      await createSecretInGroup(numGroupId, secretKey, parsedValue); // Use new function
      res.redirect(`/admin?message=Secret+added+successfully.&messageType=success`);
    } catch (error: any) {
      console.error("Error adding secret:", error);
      let userMessage = "Error+adding+secret.+Please+check+server+logs.";
      if (error.message && error.message.includes("already exists")) {
          userMessage = "Error+adding+secret:+A+secret+with+that+key+already+exists.";
      } else if (error.message && error.message.includes("Group not found")) {
          userMessage = "Error+adding+secret:+The+specified+group+was+not+found.";
      }
      // Consider preserving form fields on error redirect if desired, by passing them in query
      res.redirect(`/admin?message=${userMessage}&messageType=error`);
    }
  });

  // Handle Update Secret
  app.post('/admin/update-secret', adminAuth, csrfProtection, async (req, res) => { // Added csrfProtection
    // Key renaming is disabled for this form. originalKey and secretKey from form should be the same.
    const { originalKey, secretKey, secretValue } = req.body;
    // currentPassword from query is removed. Bearer token handles auth.

    if (originalKey !== secretKey) {
        // This UI path for editing secrets does not support renaming the key itself.
        // That would be a more complex operation (check new key conflicts, update group's key list).
        // For now, if they differ, it's an error or ignored.
        return res.redirect(`/admin/edit-secret/${encodeURIComponent(originalKey)}?message=Error+updating+secret:+Key+renaming+not+supported+via+this+form.&messageType=error`);
    }

    let parsedValue = secretValue;
    try {
        const trimmedValue = secretValue.trim();
        if ((trimmedValue.startsWith('{') && trimmedValue.endsWith('}')) || (trimmedValue.startsWith('[') && trimmedValue.endsWith(']'))) {
            parsedValue = JSON.parse(trimmedValue);
        }
    } catch (e) { /* Store as string if not valid JSON */ }

    try {
        // originalKey and secretKey are the same here due to the check above.
        if (!originalKey || typeof secretValue === 'undefined') {
            throw new Error('Secret key and value are required.');
        }
        // The old logic for key renaming (if originalKey !== secretKey) is removed.
        // We only update the value.
        await updateSecretValue(originalKey, parsedValue); // Use new function
        res.redirect(`/admin?message=Secret+value+updated+successfully.&messageType=success`);
    } catch (error: any) {
        console.error("Error updating secret value:", error);
        let userMessage = "Error+updating+secret+value.+Please+check+server+logs.";
        if (error.message && error.message.includes("not found")) {
            userMessage = "Error+updating+secret:+Secret+not+found.";
        }
        res.redirect(`/admin/edit-secret/${encodeURIComponent(originalKey)}?message=${userMessage}&messageType=error`);
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
      res.redirect(`/admin?message=Error+deleting+secret.+Please+check+server+logs.&messageType=error`);
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
      const rawPendingClients = DataManager.getPendingClients(); // synchronous
      const rawApprovedClients = DataManager.getApprovedClients(); // synchronous
      const allGroups = DataManager.getAllSecretGroups(); // synchronous

      const groupMap = new Map(allGroups.map(g => [g.id, g.name]));

      const enhanceClientWithGroupNames = (client: DataManager.ClientInfo) => ({
        ...client,
        associatedGroupNames: client.associatedGroupIds?.map(id => groupMap.get(id) || `ID ${id} (Unknown)`).join(', ') || 'None'
      });

      const pendingClients = rawPendingClients.map(enhanceClientWithGroupNames);
      const approvedClients = rawApprovedClients.map(enhanceClientWithGroupNames);

      const message = req.query.message ? { text: req.query.message.toString(), type: req.query.messageType?.toString() || 'info' } : null;

      res.render('clients', {
        pendingClients,
        approvedClients,
        password: '',
        message,
        managingClientGroups: null, // Changed from managingClientSecrets
        autoApproveWsEnabled: getConfig().autoApproveWebSocketRegistrations,
        csrfToken: req.csrfToken()
      });
    } catch (error: any) {
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
      console.error("Error approving client:", error); // Added console.error for server-side logging
      res.redirect(`/admin/clients?message=Error+approving+client.+Please+check+server+logs.&messageType=error`);
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
      console.error("Error rejecting client:", error); // Added console.error for server-side logging
      res.redirect(`/admin/clients?message=Error+rejecting+client.+Please+check+server+logs.&messageType=error`);
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
      console.error("Error revoking client:", error); // Added console.error for server-side logging
      res.redirect(`/admin/clients?message=Error+revoking+client.+Please+check+server+logs.&messageType=error`);
    }
  });

  // Route to manage a client's associated groups
  app.get('/admin/clients/:clientId/groups', adminAuth, csrfProtection, async (req, res) => {
    const { clientId } = req.params;
    try {
      const client = DataManager.getClient(clientId); // getClient is synchronous
      if (!client || client.status !== 'approved') {
        return res.redirect(`/admin/clients?message=Client+not+found+or+not+approved.&messageType=error`);
      }

      const allGroups = DataManager.getAllSecretGroups(); // synchronous
      const message = req.query.message ? { text: req.query.message.toString(), type: req.query.messageType?.toString() || 'info' } : null;

      res.render('clients', {
        pendingClients: [],
        approvedClients: [],
        password: '',
        message,
        managingClientGroups: { // Renamed from managingClientSecrets
          client: client,
          allGroups: allGroups, // Pass all available groups
          // client.associatedGroupIds is already part of the client object
        },
        autoApproveWsEnabled: getConfig().autoApproveWebSocketRegistrations,
        csrfToken: req.csrfToken()
      });
    } catch (error: any) {
      console.error("Error loading group management for client:", error); // Added console.error
      res.redirect(`/admin/clients?message=Error+loading+group+management+for+client.+Please+check+server+logs.&messageType=error`);
    }
  });

  // Route to update a client's associated groups
  app.post('/admin/clients/:clientId/groups/update', adminAuth, csrfProtection, async (req, res) => {
    const { clientId } = req.params;
    let { associatedGroupIds } = req.body; // This will be an array or single string if only one selected

    // Ensure associatedGroupIds is an array of numbers
    if (!Array.isArray(associatedGroupIds)) {
        associatedGroupIds = associatedGroupIds ? [associatedGroupIds] : [];
    }
    const groupIdsAsNumbers: number[] = associatedGroupIds.map((id: string | number) => parseInt(id.toString(), 10)).filter((id: number) => !isNaN(id));

    try {
      const client = DataManager.getClient(clientId); // synchronous
      if (!client || client.status !== 'approved') {
        throw new Error("Client not found or not approved.");
      }

      await DataManager.setClientAssociatedGroups(clientId, groupIdsAsNumbers);

      res.redirect(`/admin/clients/${clientId}/groups?message=Client+group+associations+updated.&messageType=success`);
    } catch (error: any) {
      console.error("Error updating group associations:", error); // Added console.error
      res.redirect(`/admin/clients/${clientId}/groups?message=Error+updating+group+associations.+Please+check+server+logs.&messageType=error`);
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

  // --- Phase 1: API Endpoints for Group and Secret Management (for testing) ---

  // Groups
  // API endpoint (already created in Phase 1)
  app.post('/admin/api/groups', adminAuth, csrfProtection, async (req, res) => {
    try {
      const { name } = req.body;
      if (!name) {
        res.status(400).json({ error: 'Group name is required.' });
        return;
      }
      const newGroup = await createSecretGroup(name); // Use direct import
      res.status(201).json(newGroup);
    } catch (error: any) {
      res.status(error.message.includes("already exists") ? 409 : 500).json({ error: error.message });
    }
  });

  // UI Form Handler for Creating Groups
  app.post('/admin/groups/create', adminAuth, csrfProtection, async (req, res) => {
    try {
        const { groupName } = req.body;
        if (!groupName || typeof groupName !== 'string' || groupName.trim() === "") {
            throw new Error('Group name must be a non-empty string.');
        }
        await createSecretGroup(groupName.trim());
        res.redirect('/admin?message=Secret+group+created+successfully.&messageType=success');
    } catch (error: any) {
        console.error("Error creating secret group:", error);
        let userMessage = "Error+creating+secret+group.+Please+check+server+logs.";
        if (error.message && error.message.includes("already exists")) {
            userMessage = "Error+creating+secret+group:+A+group+with+that+name+already+exists.";
        }
        res.redirect(`/admin?message=${userMessage}&messageType=error`);
    }
  });

  app.get('/admin/api/groups', adminAuth, async (req, res) => { // Should be synchronous based on DataManager
    try {
      const groups = getAllSecretGroups(); // Use direct import
      res.json(groups);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.get('/admin/api/groups/:groupId', adminAuth, async (req, res) => { // Should be synchronous
    try {
      const groupId = parseInt(req.params.groupId, 10);
      if (isNaN(groupId)) {
        res.status(400).json({ error: 'Invalid group ID format.' });
        return;
      }
      const group = getSecretGroupById(groupId); // Use direct import
      if (group) {
        res.json(group);
      } else {
        res.status(404).json({ error: 'Group not found.' });
      }
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  app.put('/admin/api/groups/:groupId', adminAuth, csrfProtection, async (req, res) => {
    try {
      const groupId = parseInt(req.params.groupId, 10);
      const { name } = req.body;
      if (isNaN(groupId)) {
        res.status(400).json({ error: 'Invalid group ID format.' });
        return;
      }
      if (!name) {
        res.status(400).json({ error: 'New group name is required.' });
        return;
      }
      await renameSecretGroup(groupId, name); // Use direct import
      res.status(200).json({ message: 'Group renamed successfully.' });
    } catch (error: any) {
      res.status(error.message.includes("not found") ? 404 : error.message.includes("already exists") ? 409 : 500).json({ error: error.message });
    }
  });

  app.delete('/admin/api/groups/:groupId', adminAuth, csrfProtection, async (req, res) => {
    try {
      const groupId = parseInt(req.params.groupId, 10);
      if (isNaN(groupId)) {
        res.status(400).json({ error: 'Invalid group ID format.' });
        return;
      }
      await deleteSecretGroup(groupId); // Use direct import
      res.status(200).json({ message: 'Group and its secrets deleted successfully.' });
    } catch (error: any) {
      res.status(error.message.includes("not found") ? 404 : 500).json({ error: error.message });
    }
  });

  // Secrets (within groups)
  app.post('/admin/api/secrets', adminAuth, csrfProtection, async (req, res) => {
    try {
      const { groupId, key, value } = req.body;
      if (typeof groupId !== 'number' || !key || value === undefined) {
        res.status(400).json({ error: 'groupId (number), key (string), and value are required.' });
        return;
      }
      await createSecretInGroup(groupId, key, value); // Use direct import
      res.status(201).json({ message: 'Secret created successfully in group.' });
    } catch (error: any) {
      res.status(error.message.includes("not found") ? 404 : error.message.includes("already exists") ? 409 : 500).json({ error: error.message });
    }
  });

  app.put('/admin/api/secrets/:key', adminAuth, csrfProtection, async (req, res) => {
    try {
      const { key } = req.params;
      const { value } = req.body;
      if (value === undefined) {
        res.status(400).json({ error: 'New value is required.' });
        return;
      }
      await updateSecretValue(key, value); // Use direct import
      res.status(200).json({ message: 'Secret value updated successfully.' });
    } catch (error: any) {
      res.status(error.message.includes("not found") ? 404 : 500).json({ error: error.message });
    }
  });

  app.delete('/admin/api/secrets/:key', adminAuth, csrfProtection, async (req, res) => {
    try {
      const { key } = req.params;
      await deleteSecret(key); // Use direct import
      res.status(200).json({ message: 'Secret deleted successfully.' });
    } catch (error: any) {
      // deleteSecret in DataManager currently doesn't throw if key not found, just warns.
      // If it were to throw, a 404 check would be good here.
      res.status(500).json({ error: error.message });
    }
  });

  app.get('/admin/api/secrets/:key', adminAuth, async (req, res) => { // Should be synchronous
    try {
      const { key } = req.params;
      const secret = getSecretWithValue(key); // Use direct import
      if (secret) {
        res.json(secret);
      } else {
        res.status(404).json({ error: 'Secret not found.' });
      }
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });


  return server; // Return the Node.js HTTP server instance
}
