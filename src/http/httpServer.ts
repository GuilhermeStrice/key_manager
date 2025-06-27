// HTTP server and admin UI logic
import express from 'express';
import path from 'path';
import * as DataManager from '../lib/dataManager'; // Import DataManager functions

// This is a very basic way to hold the password for the session.
// In a more complex app, this would be handled more securely, perhaps not stored directly.
let serverAdminPasswordSingleton: string | null = null;

export function startHttpServer(port: number, serverAdminPassword?: string) {
  const app = express();

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


  // Simple password protection for all /admin routes
  // TODO: Implement proper session-based authentication for the admin panel
  const adminAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (!serverAdminPasswordSingleton) {
        console.warn('Admin password not set for HTTP server. Admin routes will be inaccessible.');
        return res.status(500).send('Admin interface not configured.');
    }

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7); // Extract token from "Bearer <token>"
        if (token === serverAdminPasswordSingleton) {
            return next();
        }
    }

    // For initial access or if not using Bearer token, check query param (less secure, for simplicity)
    // Or provide a login form.
    if (req.query.password === serverAdminPasswordSingleton) {
      return next();
    }

    // Simple login page
    if (req.path === '/admin/login' && req.method === 'GET') {
        return res.send(`
            <h1>Admin Login</h1>
            <form action="/admin/login" method="POST">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
                <button type="submit">Login</button>
            </form>
            <p>Hint: Use the server startup password.</p>
        `);
    }

    if (req.path === '/admin/login' && req.method === 'POST') {
        if (req.body.password === serverAdminPasswordSingleton) {
            // In a real app, set a session cookie here.
            // For now, we'll just redirect and expect the password for other /admin routes.
            // Or, for simplicity, we can just let them proceed if they POSTed correctly,
            // but that's not how typical sessions work.
            // A better approach for this simple case might be to just always require the password
            // as a query param or bearer token for all admin actions after this.
            // Let's stick to the Bearer token / query param for subsequent requests.
            // This login form is more for show until proper sessions are built.
            return res.send("<p>Logged in (conceptually). Please use the password as a 'password' query parameter or 'Authorization: Bearer your_password' header for other admin routes.</p><a href='/admin?password="+encodeURIComponent(req.body.password)+"'>Proceed to Admin</a>");
        } else {
            return res.status(401).send('<h1>Admin Login</h1><p>Incorrect password.</p><form action="/admin/login" method="POST"><label for="password">Password:</label><input type="password" id="password" name="password" required><button type="submit">Login</button></form>');
        }
    }

    // If trying to access other /admin routes without auth
    if (req.path.startsWith('/admin') && req.path !== '/admin/login') {
        return res.status(401).redirect('/admin/login');
    }

    // For non-admin routes
    next();
  };

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

  app.post('/admin/login', express.urlencoded({ extended: false }), (req, res) => {
     if (req.body.password && req.body.password === serverAdminPasswordSingleton) {
        // In a real app: set a signed cookie for session management.
        // For now, just acknowledge. User will need to supply password for other routes.
        // Redirecting to /admin with password in query for demo purposes.
        res.redirect(`/admin?password=${encodeURIComponent(req.body.password)}`);
    } else {
        res.status(401).send('Login failed. <a href="/admin/login">Try again</a>');
    }
  });


  // Protected admin route
  app.get('/admin', adminAuth, async (req, res) => {
    try {
      const allKeys = DataManager.getAllKeys();
      const secrets = allKeys.map(key => ({
        key,
        value: DataManager.getItem(key)
      }));
      const currentPassword = req.query.password?.toString() || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : '');
      const message = req.query.message ? { text: req.query.message.toString(), type: req.query.messageType?.toString() || 'info' } : null;

      res.render('admin', {
        secrets,
        password: currentPassword,
        message,
        editingItemKey: null,
        itemToEdit: null
      });
    } catch (error) {
      console.error("Error rendering admin page:", error);
      res.status(500).send("Error loading admin page.");
    }
  });

  // Route to show edit form
  app.get('/admin/edit-secret/:key', adminAuth, async (req, res) => {
    try {
        const itemKey = decodeURIComponent(req.params.key);
        const itemToEdit = DataManager.getItem(itemKey);
        const currentPassword = req.query.password?.toString() || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : '');

        if (itemToEdit === undefined) {
            return res.redirect(`/admin?password=${encodeURIComponent(currentPassword)}&message=Secret+not+found&messageType=error`);
        }

        const allKeys = DataManager.getAllKeys();
        const secrets = allKeys.map(key => ({ key, value: DataManager.getItem(key) }));

        res.render('admin', {
            secrets,
            password: currentPassword,
            message: null,
            editingItemKey: itemKey,
            itemToEdit: itemToEdit
        });
    } catch (error) {
        console.error("Error rendering edit page:", error);
        const currentPassword = req.query.password?.toString() || '';
        res.redirect(`/admin?password=${encodeURIComponent(currentPassword)}&message=Error+loading+edit+page&messageType=error`);
    }
  });

  // Handle Add Secret
  app.post('/admin/add-secret', adminAuth, async (req, res) => {
    const { secretKey, secretValue } = req.body;
    const currentPassword = req.query.password?.toString() || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : '');
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
      if (DataManager.getItem(secretKey) !== undefined) {
        throw new Error('Secret key already exists. Use edit to modify.');
      }
      await DataManager.setItem(secretKey, parsedValue);
      res.redirect(`/admin?password=${encodeURIComponent(currentPassword)}&message=Secret+added&messageType=success`);
    } catch (error: any) {
      console.error("Error adding secret:", error);
      res.redirect(`/admin?password=${encodeURIComponent(currentPassword)}&message=Error+adding+secret:+${encodeURIComponent(error.message)}&messageType=error`);
    }
  });

  // Handle Update Secret
  app.post('/admin/update-secret', adminAuth, async (req, res) => {
    const { originalKey, secretKey, secretValue } = req.body;
    const currentPassword = req.query.password?.toString() || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : '');
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
            if (DataManager.getItem(secretKey) !== undefined) {
                 throw new Error(`New key "${secretKey}" already exists. Choose a different key.`);
            }
            await DataManager.deleteItem(originalKey);
            await DataManager.setItem(secretKey, parsedValue);
        } else {
            await DataManager.setItem(originalKey, parsedValue);
        }
        res.redirect(`/admin?password=${encodeURIComponent(currentPassword)}&message=Secret+updated&messageType=success`);
    } catch (error: any) {
        console.error("Error updating secret:", error);
        res.redirect(`/admin/edit-secret/${encodeURIComponent(originalKey)}?password=${encodeURIComponent(currentPassword)}&message=Error+updating+secret:+${encodeURIComponent(error.message)}&messageType=error`);
    }
  });

  // Handle Delete Secret
  app.post('/admin/delete-secret/:key', adminAuth, async (req, res) => {
    const itemKey = decodeURIComponent(req.params.key);
    const currentPassword = req.query.password?.toString() || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : '');
    try {
      await DataManager.deleteItem(itemKey);
      res.redirect(`/admin?password=${encodeURIComponent(currentPassword)}&message=Secret+deleted&messageType=success`);
    } catch (error: any) {
      console.error("Error deleting secret:", error);
      res.redirect(`/admin?password=${encodeURIComponent(currentPassword)}&message=Error+deleting+secret:+${encodeURIComponent(error.message)}&messageType=error`);
    }
  });

  app.get('/admin/logout', adminAuth, (req, res) => {
    const currentPassword = req.query.password?.toString() || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.substring(7) : '');
    res.send(`Logged out (conceptually). <a href="/admin/login?password=${encodeURIComponent(currentPassword)}">Login again</a>`);
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

  return server; // Return the Node.js HTTP server instance
}
