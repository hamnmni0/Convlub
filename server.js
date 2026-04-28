const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 8000);
const HOST = process.env.HOST || "0.0.0.0";
const COOKIE_NAME = "convlub_session";
const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "store.json");
const CONFIG_FILE = path.join(__dirname, "server-config.json");

const sessions = new Map();

const defaultStore = {
  settings: {
    siteName: "ConvLub",
    featuredEventId: "dinner-party",
    countdownTarget: "2026-05-08T19:00:00+03:00",
  },
  events: [
    {
      id: "dinner-party",
      name: "ConvLub Dinner Party",
      description:
        "A flagship dinner for curated introductions, warm hospitality, and meaningful conversations around a shared table.",
      location: "Basma Mezze & Grill, Kuwait City",
      dateLabel: "May 1, 2026",
      timeLabel: "7:00 PM AST",
      seatsLeft: 34,
      tags: ["Upcoming", "Dinner", "Featured"],
    },
    {
      id: "creative-supper",
      name: "Creative Supper Circle",
      description:
        "A smaller table for designers, founders, and operators who want intentional networking rather than open mingling.",
      location: "Noura Hall, Salmiya",
      dateLabel: "May 21, 2026",
      timeLabel: "8:00 PM AST",
      seatsLeft: 18,
      tags: ["Upcoming", "Networking", "Salon"],
    },
    {
      id: "founder-breakfast",
      name: "Founder Breakfast Briefing",
      description:
        "A breakfast format for tighter conversations, short updates, and invite-led attendance.",
      location: "The Yard Lounge, Kuwait City",
      dateLabel: "June 2, 2026",
      timeLabel: "9:30 AM AST",
      seatsLeft: 22,
      tags: ["Upcoming", "Breakfast", "Invite"],
    },
  ],
  pastEvents: [
    {
      id: "ramadan-reflection",
      name: "Ramadan Reflection Forum",
      description:
        "A community-focused evening with storytelling, iftar, and guided small-group conversations.",
      attendance: 112,
      partner: "Heritage Kitchen",
      dateLabel: "March 21, 2026",
    },
    {
      id: "winter-salon",
      name: "Winter Founder Salon",
      description:
        "A private dinner for startup operators with tasting menu service and moderated discussion.",
      attendance: 55,
      partner: "Safa Courtyard",
      dateLabel: "January 14, 2026",
    },
  ],
  menuItems: [
    {
      id: "mezze-platter",
      name: "Signature Mezze Platter",
      description: "Hummus, muhammara, vine leaves, and warm flatbread.",
      price: 8.5,
    },
    {
      id: "mixed-grill",
      name: "Mixed Grill Selection",
      description: "Chicken taouk, lamb kofta, grilled vegetables, and saffron rice.",
      price: 14.0,
    },
    {
      id: "rose-cheesecake",
      name: "Rose Cheesecake",
      description: "Rosewater cheesecake finished with pistachio crumble.",
      price: 6.5,
    },
    {
      id: "date-cooler",
      name: "Sparkling Date Cooler",
      description: "A chilled date, mint, and citrus mocktail.",
      price: 4.25,
    },
  ],
  registrations: [
    {
      id: crypto.randomUUID(),
      createdAt: "2026-04-19T10:15:00.000Z",
      name: "Noura Al Sabah",
      email: "noura@studionorth.com",
      phone: "+965 9999 1111",
      company: "Studio North",
      eventId: "dinner-party",
      ticketType: "Hosted Seat",
      notes: "No nuts",
      menuIds: ["mezze-platter", "date-cooler"],
    },
    {
      id: crypto.randomUUID(),
      createdAt: "2026-04-20T08:45:00.000Z",
      name: "Ahmad Darwish",
      email: "ahmad@ventureio.com",
      phone: "+965 9555 3333",
      company: "Venture IO",
      eventId: "creative-supper",
      ticketType: "Member Ticket",
      notes: "Vegetarian",
      menuIds: ["rose-cheesecake"],
    },
  ],
};

const defaultConfig = {
  adminEmail: "admin@convlub.local",
  adminPassword: "ChangeMe123!",
  passwordSalt: crypto.randomBytes(16).toString("hex"),
  passwordHash: "",
  sessionSecret: crypto.randomBytes(32).toString("hex"),
};

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function ensureConfig() {
  if (!fs.existsSync(CONFIG_FILE)) {
    const config = { ...defaultConfig };
    config.passwordHash = hashPassword("ChangeMe123!", config.passwordSalt);
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  }

  const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
  if (!config.sessionSecret) {
    throw new Error("server-config.json is missing required security fields.");
  }
  return config;
}

function ensureStore() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(defaultStore, null, 2));
  }
}

function readStore() {
  ensureStore();
  return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
}

function writeStore(store) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(store, null, 2));
}

function sendJson(response, statusCode, payload, headers = {}) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...headers,
  });
  response.end(JSON.stringify(payload));
}

function sendText(response, statusCode, payload, headers = {}) {
  response.writeHead(statusCode, {
    "Content-Type": "text/plain; charset=utf-8",
    ...headers,
  });
  response.end(payload);
}

function parseCookies(request) {
  const header = request.headers.cookie || "";
  return header
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((cookies, pair) => {
      const separatorIndex = pair.indexOf("=");
      if (separatorIndex === -1) return cookies;
      const key = pair.slice(0, separatorIndex);
      const value = pair.slice(separatorIndex + 1);
      cookies[key] = decodeURIComponent(value);
      return cookies;
    }, {});
}

function setSessionCookie(response, token) {
  response.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${encodeURIComponent(
      token
    )}; HttpOnly; Path=/; SameSite=Strict; Max-Age=28800`
  );
}

function clearSessionCookie(response) {
  response.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0`
  );
}

function createSession(config, email) {
  const token = crypto
    .createHmac("sha256", config.sessionSecret)
    .update(`${email}:${Date.now()}:${crypto.randomUUID()}`)
    .digest("hex");
  sessions.set(token, { email, expiresAt: Date.now() + 8 * 60 * 60 * 1000 });
  return token;
}

function getSession(request) {
  const cookies = parseCookies(request);
  const token = cookies[COOKIE_NAME];
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { token, ...session };
}

function maskEmail(email) {
  const [name, domain] = email.split("@");
  if (!name || !domain) return email;
  return `${name.slice(0, 2)}***@${domain}`;
}

function getSummary(store) {
  const registrations = store.registrations;
  const orders = registrations.reduce(
    (total, registration) => total + registration.menuIds.length,
    0
  );
  const menuRevenue = registrations.reduce((total, registration) => {
    return (
      total +
      registration.menuIds.reduce((menuTotal, menuId) => {
        const item = store.menuItems.find((entry) => entry.id === menuId);
        return menuTotal + (item ? item.price : 0);
      }, 0)
    );
  }, 0);

  return {
    registrations: registrations.length,
    orders,
    menuRevenue,
  };
}

function buildPublicPayload(store, adminLoggedIn) {
  const menuOrderCounts = Object.fromEntries(
    store.menuItems.map((item) => [
      item.id,
      store.registrations.filter((registration) =>
        registration.menuIds.includes(item.id)
      ).length,
    ])
  );

  return {
    settings: store.settings,
    events: store.events,
    pastEvents: store.pastEvents,
    menuItems: store.menuItems,
    summary: getSummary(store),
    menuOrderCounts,
    adminLoggedIn,
  };
}

async function readBody(request) {
  const chunks = [];
  let totalLength = 0;

  for await (const chunk of request) {
    totalLength += chunk.length;
    if (totalLength > 1024 * 1024) {
      throw new Error("Request body too large.");
    }
    chunks.push(chunk);
  }

  if (chunks.length === 0) {
    return {};
  }

  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function validateRegistration(input, store) {
  const name = String(input.name || "").trim();
  const email = String(input.email || "").trim();
  const phone = String(input.phone || "").trim();
  const company = String(input.company || "").trim();
  const eventId = String(input.eventId || "").trim();
  const ticketType = String(input.ticketType || "").trim();
  const notes = String(input.notes || "").trim();
  const menuIds = Array.isArray(input.menuIds) ? input.menuIds.map(String) : [];

  if (name.length < 2) {
    return { error: "Please enter a valid full name." };
  }
  if (!email.includes("@") || !email.includes(".")) {
    return { error: "Please enter a valid email address." };
  }
  if (phone.length < 8) {
    return { error: "Please enter a valid phone number." };
  }

  const selectedEvent = store.events.find((event) => event.id === eventId);
  if (!selectedEvent) {
    return { error: "Please choose a valid event." };
  }

  const allowedTickets = ["Member Ticket", "Hosted Seat", "Guest List"];
  if (!allowedTickets.includes(ticketType)) {
    return { error: "Please choose a valid ticket type." };
  }

  const validMenuIds = menuIds.filter((menuId) =>
    store.menuItems.some((item) => item.id === menuId)
  );

  return {
    value: {
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      name,
      email,
      phone,
      company,
      eventId,
      ticketType,
      notes,
      menuIds: validMenuIds,
    },
  };
}

function serveStaticFile(request, response) {
  const requestedPath = request.url === "/" ? "/index.html" : request.url;
  const safePath = path.normalize(requestedPath).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(__dirname, safePath);

  if (!filePath.startsWith(__dirname)) {
    sendText(response, 403, "Forbidden");
    return;
  }

  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    sendText(response, 404, "Not Found");
    return;
  }

  const extension = path.extname(filePath).toLowerCase();
  const contentTypes = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml",
  };

  response.writeHead(200, {
    "Content-Type": contentTypes[extension] || "application/octet-stream",
  });
  fs.createReadStream(filePath).pipe(response);
}

function withSecurityHeaders(response) {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  response.setHeader("X-Frame-Options", "DENY");
}

const config = ensureConfig();
ensureStore();

const server = http.createServer(async (request, response) => {
  withSecurityHeaders(response);

  try {
    const url = new URL(request.url, `http://${request.headers.host}`);
    const store = readStore();
    const session = getSession(request);

    if (request.method === "GET" && url.pathname === "/api/site-data") {
      sendJson(response, 200, buildPublicPayload(store, Boolean(session)));
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/admin/session") {
      sendJson(response, 200, {
        loggedIn: Boolean(session),
        email: session?.email || null,
      });
      return;
    }

    if (request.method === "GET" && url.pathname === "/api/admin/registrations") {
      if (!session) {
        sendJson(response, 401, { error: "Admin login required." });
        return;
      }

      const payload = store.registrations
        .slice()
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .map((registration) => ({
          ...registration,
          maskedEmail: maskEmail(registration.email),
        }));

      sendJson(response, 200, { registrations: payload });
      return;
    }

    if (request.method === "POST" && url.pathname === "/api/register") {
      const input = await readBody(request);
      const validation = validateRegistration(input, store);
      if (validation.error) {
        sendJson(response, 400, { error: validation.error });
        return;
      }

      store.registrations.unshift(validation.value);
      writeStore(store);
      sendJson(response, 201, {
        message: "Registration saved successfully.",
        summary: getSummary(store),
      });
      return;
    }

    if (request.method === "POST" && url.pathname === "/api/admin/login") {
      const input = await readBody(request);
      const email = String(input.email || "").trim().toLowerCase();
      const password = String(input.password || "");
      const hashMatches =
        config.passwordHash &&
        config.passwordSalt &&
        hashPassword(password, config.passwordSalt) === config.passwordHash;
      const plainMatches = config.adminPassword && password === config.adminPassword;

      if (
        email !== config.adminEmail.toLowerCase() ||
        (!hashMatches && !plainMatches)
      ) {
        sendJson(response, 401, { error: "Invalid admin credentials." });
        return;
      }

      const token = createSession(config, config.adminEmail);
      setSessionCookie(response, token);
      sendJson(response, 200, { message: "Admin login successful." });
      return;
    }

    if (request.method === "POST" && url.pathname === "/api/admin/logout") {
      const currentSession = getSession(request);
      if (currentSession) {
        sessions.delete(currentSession.token);
      }
      clearSessionCookie(response);
      sendJson(response, 200, { message: "Logged out." });
      return;
    }

    if (request.method === "POST" && url.pathname === "/api/admin/clear-registrations") {
      if (!session) {
        sendJson(response, 401, { error: "Admin login required." });
        return;
      }

      store.registrations = [];
      writeStore(store);
      sendJson(response, 200, { message: "Registrations cleared." });
      return;
    }

    if (request.method === "GET") {
      serveStaticFile(request, response);
      return;
    }

    sendText(response, 405, "Method Not Allowed");
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unexpected server error.";
    sendJson(response, 500, { error: message });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`ConvLub server running on http://localhost:${PORT}`);
  console.log("Admin email:", config.adminEmail);
  console.log("Default admin password:", config.adminPassword || "configured via hash");
  console.log("Change the password in server-config.json before public launch.");
});
