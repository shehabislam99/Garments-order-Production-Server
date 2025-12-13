// server/index.js - Complete Backend (All-in-One)

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const path = require("path");
const fileUpload = require("express-fileupload");

// ================ EXTERNAL SDK IMPORTS ================
const admin = require("firebase-admin");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
// ======================================================

const app = express();

// ================ FIREBASE INITIALIZATION ================
let firebaseApp;
let firebaseAuth;
let firestore;
let storage;

try {
  const serviceAccount = JSON.parse(
    process.env.FIREBASE_SERVICE_ACCOUNT || "{}"
  );

  firebaseApp = admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  });

  firebaseAuth = admin.auth();
  firestore = admin.firestore();
  storage = admin.storage().bucket();

  console.log("✅ Firebase initialized successfully");
} catch (error) {
  console.error("❌ Firebase initialization failed:", error.message);
  // Mock Firebase for development
  firebaseAuth = {
    verifyIdToken: async (token) => ({
      uid: "mock-uid",
      email: "test@example.com",
      role: "buyer",
    }),
    createCustomToken: async (uid) => "mock-token-" + Date.now(),
    createUser: async (data) => ({ uid: "mock-" + Date.now(), ...data }),
    getUserByEmail: async (email) => ({
      uid: "mock-" + Date.now(),
      email,
      displayName: "Test User",
    }),
  };
  firestore = {
    collection: (name) => ({
      add: async (data) => ({ id: "mock-id-" + Date.now() }),
      doc: (id) => ({
        get: async () => ({
          data: () => ({
            id,
            email: "test@example.com",
            name: "Test User",
            role: "buyer",
            createdAt: new Date().toISOString(),
          }),
        }),
        update: async (data) => console.log("Mock update:", data),
        delete: async () => console.log("Mock delete"),
      }),
      where: (field, op, value) => ({
        get: async () => ({
          docs: [
            {
              data: () => ({
                email: value,
                name: "Test User",
                role: "buyer",
              }),
            },
          ],
        }),
      }),
      get: async () => ({
        size: 0,
        docs: [],
      }),
    }),
  };
}

// ================ SERVICES INITIALIZATION ================

// Email Service
const emailService = {
  transporter: nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  }),

  sendWelcomeEmail: async (to, name) => {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to,
      subject: "Welcome to Our Store!",
      html: `<h1>Welcome ${name}!</h1><p>Thank you for joining our store.</p>`,
    };
    try {
      await emailService.transporter.sendMail(mailOptions);
      console.log(`✅ Welcome email sent to ${to}`);
    } catch (error) {
      console.error("❌ Email sending failed:", error);
    }
  },

  sendOrderConfirmation: async (to, orderId) => {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to,
      subject: "Order Confirmation",
      html: `<h1>Order #${orderId} Confirmed!</h1><p>Your order has been received.</p>`,
    };
    try {
      await emailService.transporter.sendMail(mailOptions);
      console.log(`✅ Order confirmation sent for order ${orderId}`);
    } catch (error) {
      console.error("❌ Email sending failed:", error);
    }
  },
};

// Payment Service (Stripe)
const paymentService = {
  createPaymentIntent: async (amount, metadata = {}) => {
    try {
      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100),
        currency: "usd",
        metadata,
      });
      return paymentIntent.client_secret;
    } catch (error) {
      console.error("❌ Payment intent creation failed:", error);
      throw error;
    }
  },

  createCheckoutSession: async (items, successUrl, cancelUrl) => {
    try {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: items.map((item) => ({
          price_data: {
            currency: "usd",
            product_data: {
              name: item.name,
              images: [item.image],
            },
            unit_amount: Math.round(item.price * 100),
          },
          quantity: item.quantity,
        })),
        mode: "payment",
        success_url: successUrl,
        cancel_url: cancelUrl,
      });
      return session.url;
    } catch (error) {
      console.error("❌ Checkout session creation failed:", error);
      throw error;
    }
  },
};

// Analytics Utilities
const analytics = {
  trackEvent: async (eventName, userId, properties = {}) => {
    console.log(`📊 Analytics: ${eventName}`, {
      userId,
      properties,
      timestamp: new Date().toISOString(),
    });
    return true;
  },

  getDashboardStats: async (timeRange = "7d") => {
    // In production, query Firestore for real data
    if (firestore.collection) {
      try {
        const usersSnapshot = await firestore.collection("users").get();
        const ordersSnapshot = await firestore.collection("orders").get();

        return {
          totalUsers: usersSnapshot.size,
          totalOrders: ordersSnapshot.size,
          totalRevenue: 0, // Calculate from orders
          activeUsers: usersSnapshot.size,
          conversionRate: 2.3,
        };
      } catch (error) {
        console.error("Analytics error:", error);
      }
    }

    // Fallback mock data
    return {
      totalUsers: 150,
      totalOrders: 320,
      totalRevenue: 12500,
      activeUsers: 45,
      conversionRate: 2.3,
    };
  },
};

// File Upload Helper
const fileUploadService = {
  uploadToFirebase: async (fileBuffer, fileName, folder = "uploads") => {
    try {
      const file = storage.file(`${folder}/${fileName}`);
      await file.save(fileBuffer, {
        metadata: { contentType: "image/jpeg" },
      });
      const [url] = await file.getSignedUrl({
        action: "read",
        expires: "03-01-2500",
      });
      return url;
    } catch (error) {
      console.error("❌ Firebase upload failed:", error);
      // Fallback to local storage
      const localPath = path.join(__dirname, "uploads", fileName);
      require("fs").writeFileSync(localPath, fileBuffer);
      return `/uploads/${fileName}`;
    }
  },

  deleteFile: async (fileUrl) => {
    try {
      const fileName = fileUrl.split("/").pop();
      const file = storage.file(`uploads/${fileName}`);
      await file.delete();
      console.log(`✅ File deleted: ${fileName}`);
    } catch (error) {
      console.error("❌ File deletion failed:", error);
    }
  },
};

// ================ MIDDLEWARE FUNCTIONS ================

// Authentication middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const decodedToken = await firebaseAuth.verifyIdToken(token);
    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email,
      role: decodedToken.role || "buyer",
    };

    next();
  } catch (error) {
    console.error("Authentication error:", error);
    res.status(401).json({ error: "Invalid token" });
  }
};

// Authorization middleware
const authorize = (allowedRoles = []) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: "Authentication required" });
    }

    if (allowedRoles.length > 0 && !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Insufficient permissions",
        requiredRoles: allowedRoles,
        userRole: req.user.role,
      });
    }

    next();
  };
};

// Error handler middleware
const errorHandler = (err, req, res, next) => {
  console.error("Server Error:", err);

  const statusCode = err.statusCode || 500;
  const message = err.message || "Internal Server Error";

  res.status(statusCode).json({
    success: false,
    error: message,
    stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
  });
};

// ================ DATABASE MODELS ================

const User = {
  create: async (data) => {
    const userRef = await firestore.collection("users").add(data);
    return { id: userRef.id, ...data };
  },

  findById: async (id) => {
    const doc = await firestore.collection("users").doc(id).get();
    return doc.exists ? { id: doc.id, ...doc.data() } : null;
  },

  findByEmail: async (email) => {
    const snapshot = await firestore
      .collection("users")
      .where("email", "==", email)
      .get();
    if (snapshot.empty) return null;
    const doc = snapshot.docs[0];
    return { id: doc.id, ...doc.data() };
  },

  update: async (id, data) => {
    await firestore.collection("users").doc(id).update(data);
    return { id, ...data };
  },

  delete: async (id) => {
    await firestore.collection("users").doc(id).delete();
    return true;
  },
};

const Product = {
  create: async (data) => {
    const productRef = await firestore.collection("products").add(data);
    return { id: productRef.id, ...data };
  },

  findAll: async () => {
    const snapshot = await firestore.collection("products").get();
    return snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
  },

  findById: async (id) => {
    const doc = await firestore.collection("products").doc(id).get();
    return doc.exists ? { id: doc.id, ...doc.data() } : null;
  },

  update: async (id, data) => {
    await firestore.collection("products").doc(id).update(data);
    return { id, ...data };
  },

  delete: async (id) => {
    await firestore.collection("products").doc(id).delete();
    return true;
  },
};

const Order = {
  create: async (data) => {
    const orderRef = await firestore.collection("orders").add(data);
    return { id: orderRef.id, ...data };
  },

  findByUserId: async (userId) => {
    const snapshot = await firestore
      .collection("orders")
      .where("userId", "==", userId)
      .get();
    return snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
  },
};

// ================ VALIDATION FUNCTIONS ================

const validations = {
  register: (data) => {
    const errors = [];
    if (!data.email?.includes("@")) errors.push("Valid email required");
    if (!data.password || data.password.length < 6)
      errors.push("Password must be at least 6 characters");
    if (!data.name?.trim()) errors.push("Name is required");
    return errors;
  },

  login: (data) => {
    const errors = [];
    if (!data.email) errors.push("Email required");
    if (!data.password) errors.push("Password required");
    return errors;
  },

  product: (data) => {
    const errors = [];
    if (!data.name?.trim()) errors.push("Product name required");
    if (!data.price || data.price <= 0) errors.push("Valid price required");
    if (!data.category?.trim()) errors.push("Category is required");
    return errors;
  },

  order: (data) => {
    const errors = [];
    if (!data.items || !Array.isArray(data.items) || data.items.length === 0) {
      errors.push("Order items are required");
    }
    if (!data.totalAmount || data.totalAmount <= 0) {
      errors.push("Valid total amount required");
    }
    return errors;
  },
};

// ================ EXPRESS APP SETUP ================

// Middleware
app.use(cors({ origin: process.env.CLIENT_URL || "http://localhost:3000" }));
app.use(helmet());
app.use(morgan("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Create uploads directory if it doesn't exist
const fs = require("fs");
if (!fs.existsSync(path.join(__dirname, "uploads"))) {
  fs.mkdirSync(path.join(__dirname, "uploads"), { recursive: true });
}

// ================ ROUTES ================

// Health Check
app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    services: {
      firebase: firebaseAuth !== undefined,
      stripe: !!process.env.STRIPE_SECRET_KEY,
      email: !!process.env.EMAIL_USER,
    },
  });
});

// AUTH ROUTES
app.post("/api/auth/register", async (req, res, next) => {
  try {
    const errors = validations.register(req.body);
    if (errors.length > 0) return res.status(400).json({ errors });

    const { email, password, name, role = "buyer", photoURL } = req.body;

    // Check if user exists
    const existingUser = await User.findByEmail(email);
    if (existingUser)
      return res.status(400).json({ error: "User already exists" });

    // Create user in Firebase Auth
    const userRecord = await firebaseAuth.createUser({
      email,
      password,
      displayName: name,
      photoURL,
    });

    // Save additional data to Firestore
    const userData = {
      uid: userRecord.uid,
      email,
      name,
      role,
      photoURL,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    await User.create(userData);

    // Send welcome email
    await emailService.sendWelcomeEmail(email, name);

    // Track analytics
    await analytics.trackEvent("user_registered", userRecord.uid, { role });

    res.status(201).json({
      success: true,
      message: "Registration successful",
      user: userData,
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const errors = validations.login(req.body);
    if (errors.length > 0) return res.status(400).json({ errors });

    const { email, password } = req.body;

    // Note: Firebase Admin SDK doesn't verify passwords directly
    // In a real app, you'd use Firebase Client SDK for this
    // This is a simplified version

    const userData = await User.findByEmail(email);
    if (!userData)
      return res.status(401).json({ error: "Invalid credentials" });

    // Generate custom token
    const token = await firebaseAuth.createCustomToken(userData.uid);

    // Track analytics
    await analytics.trackEvent("user_login", userData.uid);

    res.json({
      success: true,
      message: "Login successful",
      user: userData,
      token,
    });
  } catch (error) {
    next(error);
  }
});

// PRODUCT ROUTES
app.get("/api/products", async (req, res, next) => {
  try {
    const products = await Product.findAll();
    res.json({
      success: true,
      count: products.length,
      products,
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/products/:id", async (req, res, next) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: "Product not found" });
    res.json({ success: true, product });
  } catch (error) {
    next(error);
  }
});

app.post(
  "/api/products",
  authenticate,
  authorize(["admin", "manager"]),
  async (req, res, next) => {
    try {
      const errors = validations.product(req.body);
      if (errors.length > 0) return res.status(400).json({ errors });

      const productData = {
        ...req.body,
        createdBy: req.user.uid,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      const product = await Product.create(productData);

      res.status(201).json({
        success: true,
        message: "Product created successfully",
        product,
      });
    } catch (error) {
      next(error);
    }
  }
);

app.put(
  "/api/products/:id",
  authenticate,
  authorize(["admin", "manager"]),
  async (req, res, next) => {
    try {
      const product = await Product.findById(req.params.id);
      if (!product) return res.status(404).json({ error: "Product not found" });

      const updatedProduct = await Product.update(req.params.id, {
        ...req.body,
        updatedAt: new Date().toISOString(),
      });

      res.json({
        success: true,
        message: "Product updated successfully",
        product: updatedProduct,
      });
    } catch (error) {
      next(error);
    }
  }
);

// USER ROUTES
app.get("/api/users/me", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.uid);
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ success: true, user });
  } catch (error) {
    next(error);
  }
});

app.put("/api/users/me", authenticate, async (req, res) => {
  try {
    const { name, photoURL } = req.body;
    const updatedUser = await User.update(req.user.uid, {
      name,
      photoURL,
      updatedAt: new Date().toISOString(),
    });
    res.json({
      success: true,
      message: "Profile updated successfully",
      user: updatedUser,
    });
  } catch (error) {
    next(error);
  }
});

// ORDER ROUTES
app.get("/api/orders/my-orders", authenticate, async (req, res) => {
  try {
    const orders = await Order.findByUserId(req.user.uid);
    res.json({
      success: true,
      count: orders.length,
      orders,
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/orders", authenticate, async (req, res) => {
  try {
    const errors = validations.order(req.body);
    if (errors.length > 0) return res.status(400).json({ errors });

    const { items, totalAmount, shippingAddress } = req.body;

    const orderData = {
      userId: req.user.uid,
      items,
      totalAmount,
      shippingAddress,
      status: "pending",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const order = await Order.create(orderData);

    // Send order confirmation email
    const user = await User.findById(req.user.uid);
    if (user && user.email) {
      await emailService.sendOrderConfirmation(user.email, order.id);
    }

    // Track analytics
    await analytics.trackEvent("order_created", req.user.uid, {
      orderId: order.id,
      totalAmount,
      itemCount: items.length,
    });

    res.status(201).json({
      success: true,
      message: "Order created successfully",
      order,
    });
  } catch (error) {
    next(error);
  }
});

// PAYMENT ROUTES
app.post("/api/payment/create-intent", authenticate, async (req, res) => {
  try {
    const { amount, orderId } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ error: "Valid amount required" });
    }

    const clientSecret = await paymentService.createPaymentIntent(amount, {
      orderId,
    });

    res.json({
      success: true,
      clientSecret,
    });
  } catch (error) {
    next(error);
  }
});

// DASHBOARD ROUTES
app.get(
  "/api/dashboard/stats",
  authenticate,
  authorize(["admin", "manager"]),
  async (req, res) => {
    try {
      const stats = await analytics.getDashboardStats();
      res.json({
        success: true,
        stats,
      });
    } catch (error) {
      next(error);
    }
  }
);

// FILE UPLOAD ROUTE
app.post("/api/upload", authenticate, async (req, res) => {
  try {
    if (!req.files || !req.files.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const file = req.files.file;
    const fileName = `${Date.now()}-${file.name}`;

    let fileUrl;
    if (process.env.FIREBASE_STORAGE_BUCKET) {
      // Upload to Firebase Storage
      fileUrl = await fileUploadService.uploadToFirebase(file.data, fileName);
    } else {
      // Save locally
      const filePath = path.join(__dirname, "uploads", fileName);
      await file.mv(filePath);
      fileUrl = `/uploads/${fileName}`;
    }

    // Update user profile with photo URL if needed
    if (req.body.updateProfile) {
      await User.update(req.user.uid, {
        photoURL: fileUrl,
        updatedAt: new Date().toISOString(),
      });
    }

    res.json({
      success: true,
      message: "File uploaded successfully",
      fileName,
      fileUrl,
    });
  } catch (error) {
    next(error);
  }
});

// PAYMENT WEBHOOK (Stripe)
app.post(
  "/api/payment/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const sig = req.headers["stripe-signature"];
      const event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );

      if (event.type === "payment_intent.succeeded") {
        const paymentIntent = event.data.object;
        const orderId = paymentIntent.metadata.orderId;

        if (orderId) {
          // Update order status in Firestore
          await firestore.collection("orders").doc(orderId).update({
            status: "paid",
            paymentId: paymentIntent.id,
            paidAt: new Date().toISOString(),
          });

          console.log(`✅ Payment succeeded for order ${orderId}`);
        }
      }

      res.json({ received: true });
    } catch (error) {
      console.error("❌ Webhook error:", error);
      res.status(400).send(`Webhook Error: ${error.message}`);
    }
  }
);

// 404 Handler
app.use("*", (req, res) => {
  res.status(404).json({
    success: false,
    error: "Route not found",
  });
});

// Error Handler
app.use(errorHandler);

// ================ START SERVER ================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📁 Uploads directory: ${path.join(__dirname, "uploads")}`);
  console.log(`🌐 Health check: http://localhost:${PORT}/api/health`);
});
