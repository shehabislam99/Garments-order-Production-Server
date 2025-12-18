// server/index.js - Complete Backend (All-in-One)

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const path = require("path");
const fileUpload = require("express-fileupload");
// const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
// const stripe = require("stripe")(process.env.STRIPE_SECRET);

// const crypto = require("crypto");

// const admin = require("firebase-admin");

// const serviceAccount = require("./Product-Tracker-sdk.json")

// admin.initializeApp({
//   credential: admin.credential.cert(serviceAccount),
// });

// function generateTrackingId() {
//   const prefix = "PRCL"; // your brand prefix
//   const date = new Date().toISOString().slice(0, 10).replace(/-/g, ""); // YYYYMMDD
//   const random = crypto.randomBytes(3).toString("hex").toUpperCase(); // 6-char random hex

//   return `${prefix}-${date}-${random}`;
// }

// middleware


// const verifyFBToken = async (req, res, next) => {
//   const token = req.headers.authorization;

//   if (!token) {
//     return res.status(401).send({ message: "unauthorized access" });
//   }

//   try {
//     const idToken = token.split(" ")[1];
//     const decoded = await admin.auth().verifyIdToken(idToken);
//     console.log("decoded in the token", decoded);
//     req.decoded_email = decoded.email;
//     next();
//   } catch (err) {
//     return res.status(401).send({ message: "unauthorized access" });
//   }
// };

// const uri = `mongodb+srv://${process.env.Db_USERNAME}:${process.env.Db_Password}@cluster0.vyznij5.mongodb.net/?appName=Cluster0`;

// // Create a MongoClient with a MongoClientOptions object to set the Stable API version
// const client = new MongoClient(uri, {
//   serverApi: {
//     version: ServerApiVersion.v1,
//     strict: true,
//     deprecationErrors: true,
//   },
// });

// async function run() {
//   try {
//     // Connect the client to the server	(optional starting in v4.7)
//     await client.connect();

//     const db = client.db("zap_shift_db");
//     const userCollection = db.collection("users");
//     const parcelsCollection = db.collection("parcels");
//     const paymentCollection = db.collection("payments");
//     const ridersCollection = db.collection("riders");

//     // users related apis
//     app.post("/users", async (req, res) => {
//       const user = req.body;
//       user.role = "user";
//       user.createdAt = new Date();
//       const email = user.email;
//       const userExists = await userCollection.findOne({ email });

//       if (userExists) {
//         return res.send({ message: "user exists" });
//       }

//       const result = await userCollection.insertOne(user);
//       res.send(result);
//     });

//     // parcel api
//     app.get("/parcels", async (req, res) => {
//       const query = {};
//       const { email } = req.query;
//       // /parcels?email=''&
//       if (email) {
//         query.senderEmail = email;
//       }

//       const options = { sort: { createdAt: -1 } };

//       const cursor = parcelsCollection.find(query, options);
//       const result = await cursor.toArray();
//       res.send(result);
//     });

//     app.get("/parcels/:id", async (req, res) => {
//       const id = req.params.id;
//       const query = { _id: new ObjectId(id) };
//       const result = await parcelsCollection.findOne(query);
//       res.send(result);
//     });

//     app.post("/parcels", async (req, res) => {
//       const parcel = req.body;
//       // parcel created time
//       parcel.createdAt = new Date();

//       const result = await parcelsCollection.insertOne(parcel);
//       res.send(result);
//     });

//     app.delete("/parcels/:id", async (req, res) => {
//       const id = req.params.id;
//       const query = { _id: new ObjectId(id) };

//       const result = await parcelsCollection.deleteOne(query);
//       res.send(result);
//     });

//     // payment related apis
//     app.post("/payment-checkout-session", async (req, res) => {
//       const paymentInfo = req.body;
//       const amount = parseInt(paymentInfo.cost) * 100;
//       const session = await stripe.checkout.sessions.create({
//         line_items: [
//           {
//             price_data: {
//               currency: "usd",
//               unit_amount: amount,
//               product_data: {
//                 name: `Please pay for: ${paymentInfo.parcelName}`,
//               },
//             },
//             quantity: 1,
//           },
//         ],
//         mode: "payment",
//         metadata: {
//           parcelId: paymentInfo.parcelId,
//         },
//         customer_email: paymentInfo.senderEmail,
//         success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
//         cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled`,
//       });

//       res.send({ url: session.url });
//     });

//     // old
//     app.post("/create-checkout-session", async (req, res) => {
//       const paymentInfo = req.body;
//       const amount = parseInt(paymentInfo.cost) * 100;

//       const session = await stripe.checkout.sessions.create({
//         line_items: [
//           {
//             price_data: {
//               currency: "USD",
//               unit_amount: amount,
//               product_data: {
//                 name: paymentInfo.parcelName,
//               },
//             },
//             quantity: 1,
//           },
//         ],
//         customer_email: paymentInfo.senderEmail,
//         mode: "payment",
//         metadata: {
//           parcelId: paymentInfo.parcelId,
//           parcelName: paymentInfo.parcelName,
//         },
//         success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success`,
//         cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled`,
//       });

//       console.log(session);
//       res.send({ url: session.url });
//     });

//     app.patch("/payment-success", async (req, res) => {
//       const sessionId = req.query.session_id;
//       const session = await stripe.checkout.sessions.retrieve(sessionId);

//       // console.log('session retrieve', session)
//       const transactionId = session.payment_intent;
//       const query = { transactionId: transactionId };

//       const paymentExist = await paymentCollection.findOne(query);
//       console.log(paymentExist);
//       if (paymentExist) {
//         return res.send({
//           message: "already exists",
//           transactionId,
//           trackingId: paymentExist.trackingId,
//         });
//       }

//       const trackingId = generateTrackingId();

//       if (session.payment_status === "paid") {
//         const id = session.metadata.parcelId;
//         const query = { _id: new ObjectId(id) };
//         const update = {
//           $set: {
//             paymentStatus: "paid",
//             trackingId: trackingId,
//           },
//         };

//         const result = await parcelsCollection.updateOne(query, update);

//         const payment = {
//           amount: session.amount_total / 100,
//           currency: session.currency,
//           customerEmail: session.customer_email,
//           parcelId: session.metadata.parcelId,
//           parcelName: session.metadata.parcelName,
//           transactionId: session.payment_intent,
//           paymentStatus: session.payment_status,
//           paidAt: new Date(),
//           trackingId: trackingId,
//         };

//         if (session.payment_status === "paid") {
//           const resultPayment = await paymentCollection.insertOne(payment);

//           res.send({
//             success: true,
//             modifyParcel: result,
//             trackingId: trackingId,
//             transactionId: session.payment_intent,
//             paymentInfo: resultPayment,
//           });
//         }
//       }

//       res.send({ success: false });
//     });

//     // payment related apis
//     app.get("/payments", verifyFBToken, async (req, res) => {
//       const email = req.query.email;
//       const query = {};

//       // console.log( 'headers', req.headers);

//       if (email) {
//         query.customerEmail = email;

//         // check email address
//         if (email !== req.decoded_email) {
//           return res.status(403).send({ message: "forbidden access" });
//         }
//       }
//       const cursor = paymentCollection.find(query).sort({ paidAt: -1 });
//       const result = await cursor.toArray();
//       res.send(result);
//     });

//     // riders related apis
//     app.get("/riders", async (req, res) => {
//       const query = {};
//       if (req.query.status) {
//         query.status = req.query.status;
//       }
//       const cursor = ridersCollection.find(query);
//       const result = await cursor.toArray();
//       res.send(result);
//     });

//     app.post("/riders", async (req, res) => {
//       const rider = req.body;
//       rider.status = "pending";
//       rider.createdAt = new Date();

//       const result = await ridersCollection.insertOne(rider);
//       res.send(result);
//     });

//     app.patch("/riders/:id", verifyFBToken, async (req, res) => {
//       const status = req.body.status;
//       const id = req.params.id;
//       const query = { _id: new ObjectId(id) };
//       const updatedDoc = {
//         $set: {
//           status: status,
//         },
//       };

//       const result = await ridersCollection.updateOne(query, updatedDoc);

//       if (status === "approved") {
//         const email = req.body.email;
//         const userQuery = { email };
//         const updateUser = {
//           $set: {
//             role: "rider",
//           },
//         };
//         const userResult = await userCollection.updateOne(
//           userQuery,
//           updateUser
//         );
//       }

//       res.send(result);
//     });

//     // Send a ping to confirm a successful connection
//     await client.db("admin").command({ ping: 1 });
//     console.log(
//       "Pinged your deployment. You successfully connected to MongoDB!"
//     );
//   } finally {
//     // Ensures that the client will close when you finish/error
//     // await client.close();
//   }
// }
// run().catch(console.dir);

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




  //   STATS MANAGEMENT WITH FILTERS, PAGINATION IN FRONTEND FRONTEND (FULL DATABASE)
    app.get(
      "/admin/manage-user/stats",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const stats = await userCollection
            .aggregate([
              {
                $facet: {
                  totalUsers: [{ $count: "count" }],

                  roles: [
                    {
                      $addFields: {
                        roleField: { $ifNull: ["$role", "buyer"] },
                      },
                    },
                    {
                      $group: {
                        _id: "$roleField",
                        count: { $sum: 1 },
                      },
                    },
                  ],

                  statuses: [
                    {
                      $addFields: {
                        statusField: { $ifNull: ["$status", "pending"] },
                      },
                    },
                    {
                      $group: {
                        _id: "$statusField",
                        count: { $sum: 1 },
                      },
                    },
                  ],
                },
              },
            ])
            .toArray();

          const result = stats[0] || {};

          // Initialize with default values
          const roleCounts = {
            admin: 0,
            manager: 0,
            buyer: 0,
          };

          const statusCounts = {
            active: 0,
            suspended: 0,
            pending: 0,
          };

          // Map role counts
          if (result.roles && Array.isArray(result.roles)) {
            result.roles.forEach((r) => {
              const role = r._id;
              if (role && roleCounts.hasOwnProperty(role)) {
                roleCounts[role] = r.count;
              }
            });
          }

          // Map status counts
          if (result.statuses && Array.isArray(result.statuses)) {
            result.statuses.forEach((s) => {
              const status = s._id;
              if (status && statusCounts.hasOwnProperty(status)) {
                statusCounts[status] = s.count;
              }
            });
          }

          res.status(200).json({
            success: true,
            totalUsers: result.totalUsers?.[0]?.count || 0,
            roles: roleCounts,
            statuses: statusCounts,
          });
        } catch (error) {
          console.error("Error fetching user stats:", error);
          res.status(500).json({
            success: false,
            message: "Failed to fetch user statistics",
          });
        }
      }
    );