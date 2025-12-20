const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const port = process.env.PORT || 3000;
const crypto = require("crypto");

//keyConverter
const admin = require("firebase-admin");
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8"
);
const serviceAccount = JSON.parse(decoded);
// console.log(serviceAccount.client_email);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

//middleware
app.use(express.json());
app.use(cors());

// function generateTrackingId() {
//   const prefix = "PRD"; // your brand prefix
//   const date = new Date().toISOString().slice(0, 10).replace(/-/g, ""); // YYYYMMDD
//   const random = crypto.randomBytes(3).toString("hex").toUpperCase(); // 6-char random hex

//   return `${prefix}-${date}-${random}`;
// }

const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }

  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    console.log("decoded in the token", decoded);
    req.decoded_email = decoded.email;
    next();
  } catch (err) {
    return res.status(401).send({ message: "unauthorized access" });
  }
};

const stripe = require("stripe")(process.env.STRIPE_SECRET);
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const uri = `mongodb+srv://${process.env.Db_USERNAME}:${process.env.Db_Password}@cluster0.pealo3m.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    const db = client.db("Garments_production");
    const userCollection = db.collection("user");
    const productCollection = db.collection("products");
    const orderCollection = db.collection("orders");
    const paymentCollection = db.collection("payment");
    const trackingCollection = db.collection("tracking");

    // admin activity after verifyFBToken middleware
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await userCollection.findOne(query);

      if (!user || user.role !== "admin") {
        return res.status(403).send({ message: "forbidden access" });
      }

      next();
    };
    const verifyManager = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await userCollection.findOne(query);

      if (!user || user.role !== "manager") {
        return res.status(403).send({ message: "forbidden access" });
      }

      next();
    };

    const logTracking = async (trackingId, status) => {
      const log = {
        trackingId,
        status,
        details: status.split("_").join(" "),
        createdAt: new Date(),
      };
      const result = await trackingCollection.insertOne(log);
      return result;
    };

    // payment related
    app.post("/payment-checkout-session", async (req, res) => {
      const { orderamount, product_name, orderId, senderEmail, trackingId } =
        req.body;

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: product_name,
                description: `Tracking ID: ${trackingId}`,
              },
              unit_amount: Math.round(orderamount * 100),
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        metadata: {
          orderId,
          trackingId,
          productName: product_name,
        },
        customer_email: senderEmail,
        success_url: `${process.env.CLIENT_URL}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_URL}/payment-canceled`,
      });

      res.json({
        success: true,
        url: session.url,
        sessionId: session.id,
      });
    });

    app.get("/payment-success", async (req, res) => {
      const sessionId = req.query.session_id;
      const session = await stripe.checkout.sessions.retrieve(sessionId);

      if (session.payment_status !== "paid") {
        return res.status(400).json({
          success: false,
          message: "Payment not completed",
        });
      }

      const transactionId = session.payment_intent;
      const trackingId = session.metadata.trackingId;

      const updateResult = await orderCollection.updateOne(
        { trackingId },
        {
          $set: {
            paymentStatus: "paid",
            status: "confirmed",
            transactionId,
            paidAt: new Date(),
            updatedAt: new Date(),
          },
        }
      );

      await paymentCollection.insertOne({
        amount: session.amount_total / 100,
        currency: session.currency,
        customerEmail: session.customer_email,
        transactionId,
        paymentStatus: session.payment_status,
        trackingId,
        sessionId,
        createdAt: new Date(),
      });

      res.redirect(`${process.env.CLIENT_URL}/dashboard/my-orders`);
    });

    // Generate tracking ID
    const generateTrackingId = () => {
      const timestamp = Date.now().toString().slice(-6);
      const random = Math.random().toString(36).substring(2, 6).toUpperCase();
      return `TRK${timestamp}${random}`;
    };

    // POST /orders endpoint
    app.post("/orders", async (req, res) => {
      const orderData = req.body;

      const trackingId = generateTrackingId();

      let status = "pending";
      if (orderData.paymentMethod === "Stripe") {
        status = "unpaid";
      } else if (orderData.paymentMethod === "Cash on Delivery") {
        status = "cod";
      }

      const order = {
        ...orderData,
        trackingId,
        status: status,
        paymentStatus:
          orderData.paymentMethod === "Stripe" ? "unpaid" : "pending",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await orderCollection.insertOne(order);

      res.status(201).json({
        success: true,
        order: {
          _id: result.insertedId,
          trackingId,
          totalPrice: order.totalPrice,
          paymentMethod: order.paymentMethod,
          status: order.status,
        },
        message: "Order created successfully",
      });
    });

    // get payments
    app.get("/payments", verifyFBToken, async (req, res) => {
      const email = req.query.email;
      const query = {};

      // console.log( 'headers', req.headers);

      if (email) {
        query.customerEmail = email;

        // check email address
        if (email !== req.decoded_email) {
          return res.status(403).send({ message: "forbidden access" });
        }
      }
      const cursor = paymentCollection.find(query).sort({ paidAt: -1 });
      const result = await cursor.toArray();
      res.send(result);
    });

    //user post in database
    app.post("/users", async (req, res) => {
      const userInfo = req.body;
      userInfo.createdAt = new Date();
      userInfo.status = "pending";

      const result = await userCollection.insertOne(userInfo);
      res.status(201).send({
        message: "User created successfully",
        inserted: true,
        result,
      });
    });

    //user get in frontend
    app.get("/users", verifyFBToken, async (req, res) => {
      const {
        page = 1,
        limit = 10,
        searchText = "",
        role = "all",
        status = "all",
      } = req.query;
      const pageNumber = parseInt(page);
      const pageSize = parseInt(limit);
      const skip = (pageNumber - 1) * pageSize;

      let filter = {};
      if (searchText.trim()) {
        filter.$or = [
          { name: { $regex: searchText, $options: "i" } },
          { email: { $regex: searchText, $options: "i" } },
          { displayName: { $regex: searchText, $options: "i" } },
        ];
      }

      if (role !== "all") filter.role = role;
      if (status !== "all") filter.status = status;

      const total = await userCollection.countDocuments(filter);
      const users = await userCollection
        .find(filter, { projection: { password: 0 } })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(pageSize)
        .toArray();

      res.status(200).json({
        success: true,
        data: users,
        total,
        totalPages: Math.ceil(total / pageSize),
        currentPage: pageNumber,
        perPage: pageSize,
      });
    });

    //   STATS MANAGEMENT WITH FILTERS, PAGINATION IN FRONTEND FRONTEND (FULL DATABASE)
    app.get("/users/stats", verifyFBToken, async (req, res) => {
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
      if (result.roles && Array.isArray(result.roles)) {
        result.roles.forEach((r) => {
          const role = r._id;
          if (role && roleCounts.hasOwnProperty(role)) {
            roleCounts[role] = r.count;
          }
        });
      }

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
    });

    //
    //Role update in frontend
    app.patch(
      "/admin/users/role/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const { role } = req.body;
        const user = await userCollection.findOne({ _id: new ObjectId(id) });

        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        await userCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role } }
        );

        res.status(200).json({
          success: true,
          message: `User role updated to ${role}`,
          modifiedCount: 1,
        });
      }
    );

    //user status suspend and approve in frontend
    app.patch(
      "/admin/users/status/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const { status, suspendReason = "", suspendFeedback = "" } = req.body;

        await userCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              status,
              suspendReason,
              suspendFeedback,
              updatedAt: new Date(),
            },
          }
        );

        res.status(200).json({
          success: true,
          message: `User status updated to ${status}`,
        });
      }
    );

    // ADMIN STATS IN FRONTEND (FULL DATABASE)
    app.get("/admin/stats", verifyFBToken, verifyAdmin, async (req, res) => {
      const allProducts = await productCollection.countDocuments({});

      const allOrders = await orderCollection.countDocuments({
        payment_options: { $ne: "PayFirst" },
      });
      const allUsers = await userCollection.countDocuments({});

      const totalRevenue = await paymentCollection
        .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
        .toArray();

      const pendingOrders = await orderCollection.countDocuments({
        payment_status: "pending",
      });
      res.send({
        success: true,
        data: {
          allProducts,
          pendingOrders,
          allUsers,
          allOrders,
          totalRevenue: totalRevenue[0]?.total || 0,
        },
      });
    });

    // ADMIN ANALYTICS WITH FILTERS IN FRONTEND
    app.get(
      "/admin/analytics",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { range = "month" } = req.query;
        let days;
        switch (range) {
          case "week":
            days = 7;
            break;
          case "month":
            days = 30;
            break;
          case "quarter":
            days = 90;
            break;
          case "year":
            days = 365;
            break;
          default:
            days = 30;
        }

        const [totalOrders, totalProducts, totalRevenue] = await Promise.all([
          orderCollection.countDocuments({}),
          productCollection.countDocuments({}),
          // Calculate total revenue from orders
          orderCollection
            .aggregate([
              { $match: { status: "delivered" } },
              { $group: { _id: null, total: { $sum: "$totalAmount" } } },
            ])
            .toArray(),
        ]);

        const analyticsData = {
          summary: {
            totalRevenue: totalRevenue[0]?.total || 0,
            totalOrders: totalOrders,
            newCustomers: 0,
            productsSold: 0,
            avgOrderValue:
              totalOrders > 0 ? (totalRevenue[0]?.total || 0) / totalOrders : 0,
            conversionRate: 0,
          },
        };

        res.status(200).json({
          success: true,
          data: analyticsData,
          message: "Analytics data fetched successfully",
        });
      }
    );

    // PRODUCT POST  MANAGER TO FRONTEND
    app.post("/products", async (req, res) => {
      const product = req.body;
      const trackingId = generateTrackingId();
      product.createdAt = new Date();
      product.trackingId = trackingId;

      logTracking(trackingId, "product_created");

      const result = await productCollection.insertOne(product);
      res.send(result);
    });

    // PRODUCT WITH FILTERS, PAGINATION IN FRONTEND
    app.get("/products", async (req, res) => {
      const {
        searchText = "",
        page = 1,
        limit = 10,
        category = "all",
        status = "all",
      } = req.query;

      const filterQuery = {
        ...(searchText && {
          $or: [
            { product_name: { $regex: searchText, $options: "i" } },
            { description: { $regex: searchText, $options: "i" } },
            { category: { $regex: searchText, $options: "i" } },
          ],
        }),
        ...(category !== "all" && { category }),
        ...(status === "show" && { showOnHome: true }),
        ...(status === "hide" && { showOnHome: false }),
      };

      const skip = (page - 1) * limit;

      const [products, total] = await Promise.all([
        productCollection
          .find(filterQuery)
          .sort({ createdAt: -1 })
          .skip(Number(skip))
          .limit(Number(limit))
          .toArray(),

        productCollection.countDocuments(filterQuery),
      ]);

      const formattedProducts = products.map((product) => ({
        _id: product._id,
        product_name: product.product_name,
        price: product.price,
        images: product.images,
        category: product.category,
        showOnHome: product.showOnHome || false,
        payment_Options: product.payment_Options,
        demo_video_link: product.demo_video_link,
        available_quantity: product.available_quantity,
      }));

      res.status(200).json({
        success: true,
        data: formattedProducts,
        total: total,
        page: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        limit: parseInt(limit),
      });
    });

    // get single product
    app.get("/products/:id", async (req, res) => {
      const product = await productCollection.findOne({
        _id: new ObjectId(req.params.id),
      });

      if (!product) {
        return res.status(404).json({ success: false });
      }

      const formattedProduct = {
        _id: product._id,
        product_name: product.product_name,
        description: product.description,
        price: product.price,
        images: Array.isArray(product.images) ? product.images : [],
        category: product.category,
        payment_Options: Array.isArray(product.payment_Options)
          ? product.payment_Options
          : typeof product.payment_Options === "string"
          ? product.payment_Options.split(",")
          : [],
        available_quantity: product.available_quantity,
        moq: product.moq,
      };

      res.json({
        success: true,
        data: formattedProduct,
      });
    });

    // get single order
    app.get("/order/:id", async (req, res) => {
      const order = await productCollection.findOne({
        _id: new ObjectId(req.params.id),
      });

      if (!order) {
        return res.status(404).json({ success: false });
      }

      res.json({
        success: true,
        data: order,
      });
    });

    //post order
    // app.post("/orders", async (req, res) => {
    //   const orderData = req.body;
    //   const order = {
    //     ...orderData,
    //     trackingId,
    //     status: orderData.paymentMethod === "Stripe" ? "unpaid" : "cod",
    //     createdAt: new Date(),
    //   };

    //   const result = await orderCollection.insertOne(order);

    //   res.status(201).json({
    //     success: true,
    //     order: {
    //       _id: result.insertedId,
    //       trackingId,
    //       totalPrice: order.totalPrice,
    //     },

    //     message: "order created successfully",
    //   });
    // });

    // get all orders

    app.get("/orders", async (req, res) => {
      const orders = await orderCollection
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      res.json({
        success: true,
        data: orders,
      });
    });

    //get product stats
    app.get("/products/stats", verifyFBToken, async (req, res) => {
      const [totalProducts, showOnHomeCount] = await Promise.all([
        productCollection.countDocuments({}),
        productCollection.countDocuments({ showOnHome: true }),
      ]);

      const productsByCategory = await productCollection
        .aggregate([
          {
            $group: {
              _id: { $ifNull: ["$category", "Uncategorized"] },
              count: { $sum: 1 },
            },
          },
        ])
        .toArray();

      const categoriesObj = {};
      productsByCategory.forEach((cat) => {
        const categoryName = cat._id;
        categoriesObj[categoryName] = cat.count;
      });

      const responseData = {
        totalProducts: totalProducts,
        categories: categoriesObj,
        showOnHome: showOnHomeCount,
        hiddenFromHome: totalProducts - showOnHomeCount,
      };

      res.status(200).json({
        success: true,
        data: responseData,
        message: "Product statistics fetched successfully",
      });
    });

    // show on home
    app.patch(
      "/admin/products/show-on-home/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const { showOnHome } = req.body;

        const result = await productCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { showOnHome: showOnHome, updatedAt: new Date() } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({
            success: false,
            message: "Product not found",
          });
        }

        res.status(200).json({
          success: true,
          message: showOnHome
            ? "Product is now shown on home page"
            : "Product removed from home page",
          data: { showOnHome },
        });
      }
    );

    //  Update product
    app.put(
      "/admin/products/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const updateData = req.body;
        const filteredUpdateData = {
          name: updateData.name,
          description: updateData.description || "",
          price: parseFloat(updateData.price),
          category: updateData.category,
          images: updateData.images || [],
          demoVideo: updateData.demoVideo || "",
          paymentOptions: updateData.paymentOptions || [],
          updatedAt: new Date(),
        };

        const result = await productCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: filteredUpdateData }
        );

        const updatedProduct = await productCollection.findOne({
          _id: new ObjectId(id),
        });

        res.status(200).json({
          success: true,
          message: "Product updated successfully",
          data: updatedProduct,
        });
      }
    );

    // Delete product
    app.delete(
      "/admin/products/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;

        const product = await productCollection.findOne({
          _id: new ObjectId(id),
        });

        const result = await productCollection.deleteOne({
          _id: new ObjectId(id),
        });

        res.status(200).json({
          success: true,
          message: "Product deleted successfully",
        });
      }
    );

    // app.get("/orders", verifyFBToken, async (req, res) => {
    //   const {
    //     searchText = "",
    //     page = 1,
    //     limit = 10,
    //     status = "all",
    //   } = req.query;

    //   let filterQuery = {};
    //   if (searchText && searchText.trim() !== "") {
    //     filterQuery.$or = [
    //       { orderId: { $regex: searchText, $options: "i" } },
    //       { "user.name": { $regex: searchText, $options: "i" } },
    //       { "user.email": { $regex: searchText, $options: "i" } },
    //       { "product.name": { $regex: searchText, $options: "i" } },
    //     ];
    //   }

    //   if (status && status !== "all") {
    //     filterQuery.status = status;
    //   }

    //   const skip = (parseInt(page) - 1) * parseInt(limit);
    //   const total = await orderCollection.countDocuments(filterQuery);
    //   const orders = await orderCollection
    //     .find(filterQuery)
    //     .sort({ createdAt: -1 })
    //     .skip(skip)
    //     .limit(parseInt(limit))
    //     .toArray();

    //   res.status(200).json({
    //     success: true,
    //     data: orders,
    //     total: total,
    //     page: parseInt(page),
    //     totalPages: Math.ceil(total / parseInt(limit)),
    //     limit: parseInt(limit),
    //   });
    // });

    // Get order statistics
    // app.get("/orders/stats", verifyFBToken, async (req, res) => {
    //   const stats = await orderCollection
    //     .aggregate([
    //       {
    //         $facet: {
    //           totalCount: [{ $count: "totalOrders" }],
    //           byStatus: [
    //             {
    //               $group: {
    //                 _id: "$status",
    //                 count: { $sum: 1 },
    //               },
    //             },
    //           ],
    //         },
    //       },
    //     ])
    //     .toArray();

    //   const result = stats[0] || {};

    //   // Initialize counts
    //   const statusCounts = {
    //     totalOrders: result.totalCount?.[0]?.totalOrders || 0,
    //     pending: 0,
    //     approved: 0,
    //     rejected: 0,
    //     delivered: 0,
    //     cancelled: 0,
    //   };

    //   // Map status counts
    //   if (result.byStatus && Array.isArray(result.byStatus)) {
    //     result.byStatus.forEach((stat) => {
    //       const status = stat._id?.toLowerCase();
    //       if (statusCounts.hasOwnProperty(status)) {
    //         statusCounts[status] = stat.count;
    //       }
    //     });
    //   }

    //   res.status(200).json({
    //     success: true,
    //     data: statusCounts,
    //     message: "Order statistics fetched successfully",
    //   });
    // });

    // Update order status

    app.patch(
      "/admin/orders/status/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const { status } = req.body;
        const validStatuses = [
          "pending",
          "approved",
          "rejected",
          "delivered",
          "cancelled",
        ];

        const result = await orderCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              status: status,
              updatedAt: new Date(),
            },
          }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({
            success: false,
            message: "Order not found",
          });
        }

        res.status(200).json({
          success: true,
          message: `Order status updated to ${status}`,
          data: { status },
        });
      }
    );

    // Get Buyer orders with pagination and filters
    app.get("/my-orders", verifyFBToken, async (req, res) => {
      const email = req.decoded_email;
      const {
        searchText = "",
        page = 1,
        limit = 10,
        status = "all",
      } = req.query;
      let filterQuery = { "user.email": email };
      if (searchText && searchText.trim() !== "") {
        filterQuery.$or = [
          { orderId: { $regex: searchText, $options: "i" } },
          { "product.name": { $regex: searchText, $options: "i" } },
        ];
      }

      if (status && status !== "all") {
        filterQuery.status = status;
      }

      const skip = (parseInt(page) - 1) * parseInt(limit);
      const total = await orderCollection.countDocuments(filterQuery);
      const orders = await orderCollection
        .find(filterQuery)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .toArray();

      res.status(200).json({
        success: true,
        data: orders,
        total: total,
        page: parseInt(page),
        totalPages: Math.ceil(total / parseInt(limit)),
        limit: parseInt(limit),
      });
    });

    // Get Buyer order statistics
    app.get("/my-orders/stats", verifyFBToken, async (req, res) => {
      const email = req.decoded_email;
      const stats = await orderCollection
        .aggregate([
          {
            $match: { "user.email": email },
          },
          {
            $facet: {
              totalCount: [{ $count: "totalOrders" }],
              byStatus: [
                {
                  $group: {
                    _id: "$status",
                    count: { $sum: 1 },
                  },
                },
              ],
            },
          },
        ])
        .toArray();

      const result = stats[0] || {};
      const statusCounts = {
        totalOrders: result.totalCount?.[0]?.totalOrders || 0,
        pending: 0,
        approved: 0,
        rejected: 0,
        delivered: 0,
        cancelled: 0,
      };

      if (result.byStatus && Array.isArray(result.byStatus)) {
        result.byStatus.forEach((stat) => {
          const status = stat._id?.toLowerCase();
          if (statusCounts.hasOwnProperty(status)) {
            statusCounts[status] = stat.count;
          }
        });
      }

      res.status(200).json({
        success: true,
        data: statusCounts,
        message: "Order statistics fetched successfully",
      });
    });

    // Cancel Buyer order
    app.patch("/my-orders/cancel/:id", verifyFBToken, async (req, res) => {
      const { id } = req.params;
      const email = req.decoded_email;
      const order = await orderCollection.findOne({
        _id: new ObjectId(id),
        "user.email": email,
      });

      if (!order) {
        return res.status(404).json({
          success: false,
          message: "Order not found or unauthorized",
        });
      }

      if (order.status !== "pending") {
        return res.status(400).json({
          success: false,
          message: "Only pending orders can be cancelled",
        });
      }

      const result = await orderCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status: "cancelled",
            cancelledAt: new Date(),
            updatedAt: new Date(),
          },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({
          success: false,
          message: "Order not found",
        });
      }
      res.status(200).json({
        success: true,
        message: "Order cancelled successfully",
        data: { status: "cancelled" },
      });
    });
    // Add a GET endpoint for fetching role (better for AuthProvider)
    app.get("/users/role/:email", async (req, res) => {
      const { email } = req.params;

      const user = await userCollection.findOne({ email: email });

      if (!user) {
        return res.status(200).json({
          role: "buyer",
          exists: false,
        });
      }

      res.status(200).json({
        role: user?.role || "buyer",
        exists: true,
      });
    });

    app.get("/products/order", async (req, res) => {
      const { orderEmail, deliveryStatus } = req.query;
      const query = {};

      if (orderEmail) {
        query.orderEmail = orderEmail;
      }
      if (deliveryStatus !== "product_delivered") {
        query.deliveryStatus = { $nin: ["product_delivered"] };
      } else {
        query.deliveryStatus = deliveryStatus;
      }

      const cursor = productCollection.find(query);
      const result = await cursor.toArray();
      res.send(result);
    });

    // TODO: rename this to be specific like /products/:id/assign
    app.patch("/products/:id", async (req, res) => {
      const { orderId, orderName, orderEmail, trackingId } = req.body;
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };

      const updatedDoc = {
        $set: {
          deliveryStatus: "driver_assigned",
          orderId: orderId,
          orderName: orderName,
          orderEmail: orderEmail,
        },
      };

      const result = await productCollection.updateOne(query, updatedDoc);

      // update order information
      const orderQuery = { _id: new ObjectId(orderId) };
      const orderUpdatedDoc = {
        $set: {
          workStatus: "in_delivery",
        },
      };
      const orderResult = await orderCollection.updateOne(
        orderQuery,
        orderUpdatedDoc
      );

      // log  tracking
      logTracking(trackingId, "driver_assigned");

      res.send(orderResult);
    });

    app.patch("/products/status/:id", async (req, res) => {
      const { deliveryStatus, orderId, trackingId } = req.body;

      const query = { _id: new ObjectId(req.params.id) };
      const updatedDoc = {
        $set: {
          deliveryStatus: deliveryStatus,
        },
      };

      if (deliveryStatus === "product_delivered") {
        const orderQuery = { _id: new ObjectId(orderId) };
        const orderUpdatedDoc = {
          $set: {
            workStatus: "available",
          },
        };
        const orderResult = await orderCollection.updateOne(
          orderQuery,
          orderUpdatedDoc
        );
      }

      const result = await productCollection.updateOne(query, updatedDoc);
      logTracking(trackingId, deliveryStatus);

      res.send(result);
    });

    app.delete("/products/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };

      const result = await productCollection.deleteOne(query);
      res.send(result);
    });

    app.get("/orders/delivery-per-day", async (req, res) => {
      const email = req.query.email;
      const pipeline = [
        {
          $match: {
            orderEmail: email,
            deliveryStatus: "product_delivered",
          },
        },
        {
          $lookup: {
            from: "trackings",
            localField: "trackingId",
            foreignField: "trackingId",
            as: "product_trackings",
          },
        },
        {
          $unwind: "$product_trackings",
        },
        {
          $match: {
            "product_trackings.status": "product_delivered",
          },
        },
        {
          $addFields: {
            deliveryDay: {
              $dateToString: {
                format: "%Y-%m-%d",
                date: "$product_trackings.createdAt",
              },
            },
          },
        },
        {
          $group: {
            _id: "$deliveryDay",
            deliveredCount: { $sum: 1 },
          },
        },
      ];

      const result = await productCollection.aggregate(pipeline).toArray();
      res.send(result);
    });

    // tracking
    // Order Tracking Routes
    // Get order tracking details with full tracking history
    app.get("/track-order/:orderId", verifyFBToken, async (req, res) => {
      const { orderId } = req.params;
      const email = req.decoded_email;
      const order = await orderCollection.findOne({
        $or: [{ _id: new ObjectId(orderId) }, { orderId: orderId }],
        "user.email": email,
      });

      const trackingHistory = generateTrackingHistory(order);

      let estimatedDelivery = order.estimatedDelivery;
      if (!estimatedDelivery) {
        estimatedDelivery = new Date(order.createdAt);
        estimatedDelivery.setDate(estimatedDelivery.getDate() + 7); // Default 7 days
      }
      let currentLocation = order.currentLocation;
      if (
        !currentLocation &&
        order.trackingHistory &&
        order.trackingHistory.length > 0
      ) {
        const lastUpdate =
          order.trackingHistory[order.trackingHistory.length - 1];
        currentLocation = lastUpdate.location;
      }
      let trackingNumber = order.trackingNumber;
      if (!trackingNumber) {
        trackingNumber = `TRK-${order._id
          .toString()
          .substring(0, 8)
          .toUpperCase()}-${Date.now().toString().substring(8, 12)}`;
      }
      const carrier = order.carrier || "Express Logistics";

      res.status(200).json({
        success: true,
        data: {
          order: {
            ...order,
            estimatedDelivery,
            currentLocation,
            trackingNumber,
            carrier,
          },
          trackingHistory,
          statistics: {
            totalSteps: trackingHistory.length,
            completedSteps: trackingHistory.filter(
              (t) => t.status === "completed"
            ).length,
            currentStep:
              trackingHistory.find((t) => t.status === "current") || null,
            pendingSteps: trackingHistory.filter((t) => t.status === "pending")
              .length,
          },
        },
        message: "Order tracking details fetched successfully",
      });
    });

    // Update order tracking (for admin)
    app.put(
      "/track-order/update/:orderId",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { orderId } = req.params;
          const { status, location, description, step } = req.body;

          // Find the order
          const order = await orderCollection.findOne({
            $or: [{ _id: new ObjectId(orderId) }, { orderId: orderId }],
          });

          if (!order) {
            return res.status(404).json({
              success: false,
              message: "Order not found",
            });
          }

          // Create tracking update object
          const trackingUpdate = {
            step: step || getStepFromStatus(status || order.status),
            description: description || `Order ${status || "updated"}`,
            location: location
              ? `${location.city || "Unknown"}, ${
                  location.country || "Unknown"
                }`
              : "Unknown",
            status: "completed",
            date: new Date(),
            updatedBy: req.decoded_email,
          };

          // Prepare update data
          const updateData = {
            $set: {
              updatedAt: new Date(),
            },
            $push: {
              trackingHistory: trackingUpdate,
            },
          };

          // Add status update if provided
          if (status) {
            updateData.$set.status = status;
          }

          // Add location update if provided
          if (location) {
            updateData.$set.currentLocation = location;
          }

          // Update the order
          const result = await orderCollection.updateOne(
            { _id: order._id },
            updateData
          );

          // Create tracking log
          await trackingCollection.insertOne({
            orderId: order._id,
            trackingId:
              order.trackingNumber ||
              `TRK-${order._id.toString().substring(0, 8)}`,
            status: status || "tracking_updated",
            details: description || `Tracking updated: ${step || status}`,
            location: location || {},
            updatedBy: req.decoded_email,
            createdAt: new Date(),
          });

          // Get updated order
          const updatedOrder = await orderCollection.findOne({
            _id: order._id,
          });

          res.status(200).json({
            success: true,
            data: updatedOrder,
            message: "Order tracking updated successfully",
          });
        } catch (error) {
          console.error("Error updating tracking:", error);
          res.status(500).json({
            success: false,
            message: "Server error",
          });
        }
      }
    );

    // Get tracking timeline for an order
    app.get(
      "/track-order/:orderId/timeline",
      verifyFBToken,
      async (req, res) => {
        const { orderId } = req.params;
        const email = req.decoded_email;

        const order = await orderCollection.findOne({
          $or: [{ _id: new ObjectId(orderId) }, { orderId: orderId }],
          "user.email": email,
        });

        if (!order) {
          return res.status(404).json({
            success: false,
            message: "Order not found",
          });
        }
        const trackingLogs = await trackingCollection
          .find({
            orderId: order._id,
          })
          .sort({ createdAt: 1 })
          .toArray();

        const timeline = trackingLogs.map((log) => ({
          id: log._id,
          step: log.details,
          description: log.details,
          location: log.location?.city
            ? `${log.location.city}, ${log.location.country}`
            : "Unknown",
          status:
            log.status === "product_delivered"
              ? "completed"
              : log.status === "driver_assigned"
              ? "current"
              : "pending",
          date: log.createdAt,
          icon: getIconForStatus(log.status),
        }));

        res.status(200).json({
          success: true,
          data: timeline,
          message: "Timeline fetched successfully",
        });
      }
    );

    // Helper function to generate tracking history
    function generateTrackingHistory(order) {
      const steps = [
        {
          id: 1,
          step: "Order Placed",
          description: "Your order has been confirmed and payment received",
          status: "completed",
          icon: "FaClipboardCheck",
          location: "Order Processing Center",
          date: order.createdAt,
        },
        {
          id: 2,
          step: "Processing",
          description: "Preparing your item for shipment",
          status:
            order.status === "processing"
              ? "current"
              : ["approved", "shipped", "delivered"].includes(order.status)
              ? "completed"
              : "pending",
          icon: "FaWarehouse",
          location: "Factory Warehouse",
          date: new Date(order.createdAt.getTime() + 3600000), // 1 hour later
        },
        {
          id: 3,
          step: "Quality Check",
          description: "Ensuring product meets quality standards",
          status:
            order.status === "processing"
              ? "current"
              : ["approved", "shipped", "delivered"].includes(order.status)
              ? "completed"
              : "pending",
          icon: "FaCheckCircle",
          location: "Quality Control",
          date: new Date(order.createdAt.getTime() + 7200000), // 2 hours later
        },
        {
          id: 4,
          step: "Dispatched",
          description: "Package handed over to delivery partner",
          status:
            order.status === "shipped"
              ? "current"
              : order.status === "delivered"
              ? "completed"
              : "pending",
          icon: "FaTruck",
          location: "Dispatch Center",
          date: order.estimatedDelivery
            ? new Date(order.estimatedDelivery.getTime() - 86400000) // 1 day before delivery
            : new Date(order.createdAt.getTime() + 86400000), // 1 day later
        },
        {
          id: 5,
          step: "Out for Delivery",
          description: "Package is on its way to your address",
          status: order.status === "delivered" ? "completed" : "pending",
          icon: "FaShippingFast",
          location: "In Transit",
          date: order.estimatedDelivery
            ? new Date(order.estimatedDelivery.getTime() - 3600000) // 1 hour before delivery
            : new Date(order.createdAt.getTime() + 172800000), // 2 days later
        },
        {
          id: 6,
          step: "Delivered",
          description: "Package has been delivered successfully",
          status: order.status === "delivered" ? "completed" : "pending",
          icon: "FaBox",
          location: order.shippingAddress
            ? `${order.shippingAddress.city}, ${order.shippingAddress.country}`
            : "Delivery Location",
          date:
            order.estimatedDelivery ||
            new Date(order.createdAt.getTime() + 259200000), // 3 days later
        },
      ];

      return steps;
    }
    function getStepFromStatus(status) {
      const stepMap = {
        pending: "Order Placed",
        processing: "Processing",
        approved: "Processing",
        shipped: "Dispatched",
        delivered: "Delivered",
        cancelled: "Cancelled",
      };
      return stepMap[status] || "Order Update";
    }
    function getIconForStatus(status) {
      const iconMap = {
        order_created: "FaClipboardCheck",
        processing: "FaWarehouse",
        quality_check: "FaCheckCircle",
        driver_assigned: "FaTruck",
        in_transit: "FaShippingFast",
        product_delivered: "FaBox",
        payment_received: "FaDollarSign",
        cancelled: "FaTimesCircle",
      };
      return iconMap[status] || "FaInfoCircle";
    }

    // Optional Get real-time location updates (for testing/demo)
    app.get(
      "/track-order/:orderId/location",
      verifyFBToken,
      async (req, res) => {
        const { orderId } = req.params;
        const email = req.decoded_email;

        const order = await orderCollection.findOne({
          $or: [{ _id: new ObjectId(orderId) }, { orderId: orderId }],
          "user.email": email,
        });

        const mockLocations = [
          {
            city: "Dhaka",
            country: "Bangladesh",
            latitude: 23.8103,
            longitude: 90.4125,
          },
          {
            city: "Chittagong",
            country: "Bangladesh",
            latitude: 22.3569,
            longitude: 91.7832,
          },
          {
            city: "Sylhet",
            country: "Bangladesh",
            latitude: 24.9045,
            longitude: 91.8611,
          },
          {
            city: "Khulna",
            country: "Bangladesh",
            latitude: 22.8456,
            longitude: 89.5403,
          },
        ];

        // Get current location or generate random one
        const currentLocation =
          order.currentLocation ||
          mockLocations[Math.floor(Math.random() * mockLocations.length)];

        res.status(200).json({
          success: true,
          data: {
            location: currentLocation,
            lastUpdated: new Date(),
            accuracy: "High",
            speed: Math.random() * 60 + 20, // Mock speed in km/h
            heading: Math.random() * 360, // Mock heading in degrees
          },
          message: "Location fetched successfully",
        });
      }
    );

    //Profile
    app.get("/auth/profile", verifyFBToken, async (req, res) => {
      const email = req.decoded_email;

      const user = await userCollection.findOne({ email });

      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }

      res.send({
        success: true,
        data: user,
      });
    });

    app.get("/buyer/stats", verifyFBToken, async (req, res) => {
      const email = req.decoded_email;

      const totalOrders = await productCollection.countDocuments({
        senderEmail: email,
      });

      const pendingOrders = await productCollection.countDocuments({
        senderEmail: email,
        deliveryStatus: { $ne: "product_delivered" },
      });

      const payments = await paymentCollection
        .find({ customerEmail: email })
        .toArray();

      const totalSpent = payments.reduce((sum, p) => sum + (p.amount || 0), 0);

      res.send({
        success: true,
        data: {
          totalOrders,
          pendingOrders,
          totalSpent,
          recentorders: totalOrders,
        },
      });
    });

    app.get("/notifications", verifyFBToken, async (req, res) => {
      res.send({
        success: true,
        data: [],
      });
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    //     await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("My production tracker is running");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
