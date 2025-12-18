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

function generateTrackingId() {
  const prefix = "PRD"; // your brand prefix
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, ""); // YYYYMMDD
  const random = crypto.randomBytes(3).toString("hex").toUpperCase(); // 6-char random hex

  return `${prefix}-${date}-${random}`;
}
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
    app.get(
      "/admin/analytics",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { range = "month" } = req.query;

          // Calculate days based on range
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

          // Get total counts
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

          // Prepare response data
          const analyticsData = {
            summary: {
              totalRevenue: totalRevenue[0]?.total || 0,
              totalOrders: totalOrders,
              newCustomers: 0, // You'll need to calculate this based on date range
              productsSold: 0, // Calculate from order items
              avgOrderValue:
                totalOrders > 0
                  ? (totalRevenue[0]?.total || 0) / totalOrders
                  : 0,
              conversionRate: 0, // This requires more complex calculation
            },
            // Add more data as needed
          };

          res.status(200).json({
            success: true,
            data: analyticsData,
            message: "Analytics data fetched successfully",
          });
        } catch (error) {
          console.error("Error fetching analytics:", error);
          res.status(500).json({
            success: false,
            message: "Failed to fetch analytics data",
          });
        }
      }
    );

    app.post("/products", async (req, res) => {
      const product = req.body;
      const trackingId = generateTrackingId();
      // product created time
      product.createdAt = new Date();
      product.trackingId = trackingId;

      logTracking(trackingId, "product_created");

      const result = await productCollection.insertOne(product);
      res.send(result);
    });

    // ADMIN PRODUCT MANAGEMENT WITH FILTERS, PAGINATION IN FRONTEND
    app.get("/products", verifyFBToken, async (req, res) => {
      try {
        const {
          searchText = "",
          page = 1,
          limit = 10,
          category = "all",
          status = "all",
        } = req.query;

        console.log("Fetching products with params:", {
          searchText,
          page,
          limit,
          category,
          status,
        });

        // Build filter query
        let filterQuery = {};

        if (searchText && searchText.trim() !== "") {
          filterQuery.$or = [
            { name: { $regex: searchText, $options: "i" } },
            { description: { $regex: searchText, $options: "i" } },
            { category: { $regex: searchText, $options: "i" } },
          ];
        }

        if (category && category !== "all") {
          filterQuery.category = category;
        }

        if (status === "show") {
          filterQuery.showOnHome = true;
        } else if (status === "hide") {
          filterQuery.showOnHome = false;
        }

        // Get total count
        const total = await productCollection.countDocuments(filterQuery);
        console.log("Total products matching filter:", total);

        // Calculate skip
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Fetch products
        const products = await productCollection
          .find(filterQuery)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        console.log("Products fetched:", products.length);

        // Format products
        const formattedProducts = products.map((product) => ({
          _id: product._id,
          name: product.name || "Unnamed Product",
          description: product.description || "",
          price: product.price || 0,
          image: product.image || product.images?.[0] || null,
          category: product.category || "Uncategorized",
          createdBy: product.senderEmail || product.createdBy || "Unknown",
          showOnHome: product.showOnHome || false,
          paymentOptions: product.paymentOptions || [],
          demoVideo: product.demoVideo || "",
          createdAt: product.createdAt,
          updatedAt: product.updatedAt,
        }));

        res.status(200).json({
          success: true,
          data: formattedProducts,
          total: total,
          page: parseInt(page),
          totalPages: Math.ceil(total / parseInt(limit)),
          limit: parseInt(limit),
        });
      } catch (error) {
        console.error("Error fetching products:", error);
        res.status(500).json({
          success: false,
          message: "Failed to fetch products",
        });
      }
    });

    app.get("/products/:id", verifyFBToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await productCollection.findOne(query);
      res.send(result);
    });

    // PRODUCT STATS FOR DASHBOARD IN FRONTEND
    app.get("/products/stats", verifyFBToken, async (req, res) => {
      try {
        console.log("Fetching product statistics...");

        // Get all counts in parallel for better performance
        const [totalProducts, showOnHomeCount] = await Promise.all([
          // Total products count
          productCollection.countDocuments({}),

          // Count of products shown on home
          productCollection.countDocuments({ showOnHome: true }),
        ]);

        // Get all unique categories
        const allCategories = await productCollection.distinct("category");

        // Get products by category count
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

        // Convert to the format your frontend expects
        const categoriesObj = {};
        productsByCategory.forEach((cat) => {
          const categoryName = cat._id || "Uncategorized";
          categoriesObj[categoryName] = cat.count;
        });

        // Prepare response data matching your frontend state structure
        const responseData = {
          totalProducts: totalProducts,
          categories: categoriesObj,
          showOnHome: showOnHomeCount,
          hiddenFromHome: totalProducts - showOnHomeCount,
        };

        console.log("Product stats fetched successfully");

        res.status(200).json({
          success: true,
          data: responseData,
          message: "Product statistics fetched successfully",
        });
      } catch (error) {
        console.error("Error fetching product stats:", error);

        // Return empty stats on error matching your frontend structure
        const defaultStats = {
          totalProducts: 0,
          categories: {},
          showOnHome: 0,
          hiddenFromHome: 0,
        };

        res.status(200).json({
          // Changed to 200 to prevent frontend error
          success: true, // Changed to true to prevent frontend error
          data: defaultStats,
          message: "Using default statistics",
        });
      }
    });

    // show on home
    app.patch(
      "/admin/products/show-on-home/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { id } = req.params;
          const { showOnHome } = req.body;

          console.log("Toggling show on home:", { id, showOnHome });

          // Validate input
          if (typeof showOnHome !== "boolean") {
            return res.status(400).json({
              success: false,
              message: "showOnHome must be a boolean value",
            });
          }

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
        } catch (error) {
          console.error("Error updating show on home:", error);
          res.status(500).json({
            success: false,
            message: "Failed to update product visibility",
          });
        }
      }
    );

    //  Update product
    app.put(
      "/admin/products/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { id } = req.params;
          const updateData = req.body;

          console.log("Updating product:", { id, updateData });

          // Validate required fields
          if (!updateData.name || !updateData.price || !updateData.category) {
            return res.status(400).json({
              success: false,
              message: "Name, price, and category are required fields",
            });
          }

          // Prepare update data with all fields
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

          // If there's an image field (single image)
          if (updateData.image) {
            filteredUpdateData.image = updateData.image;
          }

          const result = await productCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: filteredUpdateData }
          );

          if (result.matchedCount === 0) {
            return res.status(404).json({
              success: false,
              message: "Product not found",
            });
          }

          // Get updated product
          const updatedProduct = await productCollection.findOne({
            _id: new ObjectId(id),
          });

          res.status(200).json({
            success: true,
            message: "Product updated successfully",
            data: updatedProduct,
          });
        } catch (error) {
          console.error("Error updating product:", error);
          res.status(500).json({
            success: false,
            message: "Failed to update product",
          });
        }
      }
    );

    // Delete product
    app.delete(
      "/admin/products/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { id } = req.params;

          console.log("Deleting product:", id);

          // Check if product exists
          const product = await productCollection.findOne({
            _id: new ObjectId(id),
          });

          if (!product) {
            return res.status(404).json({
              success: false,
              message: "Product not found",
            });
          }

          const result = await productCollection.deleteOne({
            _id: new ObjectId(id),
          });

          if (result.deletedCount === 0) {
            return res.status(500).json({
              success: false,
              message: "Failed to delete product",
            });
          }

          res.status(200).json({
            success: true,
            message: "Product deleted successfully",
          });
        } catch (error) {
          console.error("Error deleting product:", error);
          res.status(500).json({
            success: false,
            message: "Failed to delete product",
          });
        }
      }
    );

    // Get orders with pagination and filters
    app.get("/orders", verifyFBToken, async (req, res) => {
      try {
        const {
          searchText = "",
          page = 1,
          limit = 10,
          status = "all",
        } = req.query;

        // Build filter query
        let filterQuery = {};

        // Search filter
        if (searchText && searchText.trim() !== "") {
          filterQuery.$or = [
            { orderId: { $regex: searchText, $options: "i" } },
            { "user.name": { $regex: searchText, $options: "i" } },
            { "user.email": { $regex: searchText, $options: "i" } },
            { "product.name": { $regex: searchText, $options: "i" } },
          ];
        }

        // Status filter
        if (status && status !== "all") {
          filterQuery.status = status;
        }

        // Calculate skip for pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Get total count
        const total = await orderCollection.countDocuments(filterQuery);

        // Fetch orders with pagination
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
      } catch (error) {
        console.error("Error fetching orders:", error);
        res.status(500).json({
          success: false,
          message: "Failed to fetch orders",
        });
      }
    });

    // Get order statistics
    app.get("/orders/stats", verifyFBToken, async (req, res) => {
      try {
        const stats = await orderCollection
          .aggregate([
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

        // Initialize counts
        const statusCounts = {
          totalOrders: result.totalCount?.[0]?.totalOrders || 0,
          pending: 0,
          approved: 0,
          rejected: 0,
          delivered: 0,
          cancelled: 0,
        };

        // Map status counts
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
      } catch (error) {
        console.error("Error fetching order stats:", error);
        res.status(500).json({
          success: false,
          message: "Failed to fetch order statistics",
        });
      }
    });

    // Update order status
    app.patch(
      "/admin/orders/status/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { id } = req.params;
          const { status } = req.body;

          // Validate status
          const validStatuses = [
            "pending",
            "approved",
            "rejected",
            "delivered",
            "cancelled",
          ];
          if (!validStatuses.includes(status)) {
            return res.status(400).json({
              success: false,
              message: "Invalid status value",
            });
          }

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
        } catch (error) {
          console.error("Error updating order status:", error);
          res.status(500).json({
            success: false,
            message: "Failed to update order status",
          });
        }
      }
    );

     app.post("/orders", async (req, res) => {
       const order = req.body;
       order.status = "pending";
       order.createdAt = new Date();

       const result = await orderCollection.insertOne(order);
       res.send(result);
     });
     
    // Get Buyer orders with pagination and filters
    app.get("/my-orders", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const {
          searchText = "",
          page = 1,
          limit = 10,
          status = "all",
        } = req.query;

        // Build filter query - only show orders for logged in user
        let filterQuery = { "user.email": email };

        // Search filter
        if (searchText && searchText.trim() !== "") {
          filterQuery.$or = [
            { orderId: { $regex: searchText, $options: "i" } },
            { "product.name": { $regex: searchText, $options: "i" } },
          ];
        }

        // Status filter
        if (status && status !== "all") {
          filterQuery.status = status;
        }

        // Calculate skip for pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Get total count
        const total = await orderCollection.countDocuments(filterQuery);

        // Fetch orders with pagination
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
      } catch (error) {
        console.error("Error fetching user orders:", error);
        res.status(500).json({
          success: false,
          message: "Failed to fetch orders",
        });
      }
    });

    // Get Buyer order statistics
    app.get("/my-orders/stats", verifyFBToken, async (req, res) => {
      try {
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

        // Initialize counts
        const statusCounts = {
          totalOrders: result.totalCount?.[0]?.totalOrders || 0,
          pending: 0,
          approved: 0,
          rejected: 0,
          delivered: 0,
          cancelled: 0,
        };

        // Map status counts
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
      } catch (error) {
        console.error("Error fetching order stats:", error);
        res.status(500).json({
          success: false,
          message: "Failed to fetch order statistics",
        });
      }
    });

    // Cancel Buyer order
    app.patch("/my-orders/cancel/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const email = req.decoded_email;

        // Find the order first
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

        // Check if order can be cancelled (only pending orders)
        if (order.status !== "pending") {
          return res.status(400).json({
            success: false,
            message: "Only pending orders can be cancelled",
          });
        }

        // Update order status
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

        // TODO: Handle refund if payment was made
        // This would integrate with your payment system

        res.status(200).json({
          success: true,
          message: "Order cancelled successfully",
          data: { status: "cancelled" },
        });
      } catch (error) {
        console.error("Error cancelling order:", error);
        res.status(500).json({
          success: false,
          message: "Failed to cancel order",
        });
      }
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
        // query.deliveryStatus = {$in: ['driver_assigned', 'order_arriving']}
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
        // update order information
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
      // log tracking
      logTracking(trackingId, deliveryStatus);

      res.send(result);
    });

    app.delete("/products/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };

      const result = await productCollection.deleteOne(query);
      res.send(result);
    });

    // payment related apis
    app.post("/payment-checkout-session", async (req, res) => {
      const productInfo = req.body;
      const amount = parseInt(productInfo.cost) * 100;
      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "usd",
              unit_amount: amount,
              product_data: {
                name: `Please pay for: ${productInfo.productName}`,
              },
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        metadata: {
          productId: productInfo.productId,
          trackingId: productInfo.trackingId,
        },
        customer_email: productInfo.senderEmail,
        success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled`,
      });

      res.send({ url: session.url });
    });

    app.patch("/payment-success", async (req, res) => {
      const sessionId = req.query.session_id;
      const session = await stripe.checkout.sessions.retrieve(sessionId);

      // console.log('session retrieve', session)
      const transactionId = session.payment_intent;
      const query = { transactionId: transactionId };

      const paymentExist = await paymentCollection.findOne(query);
      // console.log(paymentExist);
      if (paymentExist) {
        return res.send({
          message: "already exists",
          transactionId,
          trackingId: paymentExist.trackingId,
        });
      }

      // use the previous tracking id created during the product create which was set to the session metadata during session creation
      const trackingId = session.metadata.trackingId;

      if (session.payment_status === "paid") {
        const id = session.metadata.productId;
        const query = { _id: new ObjectId(id) };
        const update = {
          $set: {
            paymentStatus: "paid",
            deliveryStatus: "pending-pickup",
          },
        };

        const result = await productCollection.updateOne(query, update);

        const payment = {
          amount: session.amount_total / 100,
          currency: session.currency,
          customerEmail: session.customer_email,
          productId: session.metadata.productId,
          productName: session.metadata.productName,
          transactionId: session.payment_intent,
          paymentStatus: session.payment_status,
          paidAt: new Date(),
          trackingId: trackingId,
        };

        const resultPayment = await paymentCollection.insertOne(payment);

        logTracking(trackingId, "product_paid");

        return res.send({
          success: true,
          modifyproduct: result,
          trackingId: trackingId,
          transactionId: session.payment_intent,
          paymentInfo: resultPayment,
        });
      }
      return res.send({ success: false });
    });

    // payment 
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

    app.get("/orders/delivery-per-day", async (req, res) => {
      const email = req.query.email;
      // aggregate on product
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
          // convert timestamp to YYYY-MM-DD string
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
          // group by date
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
    app.get("/track-order/:orderId", verifyFBToken, async (req, res) => {
      try {
        const { orderId } = req.params;
        const email = req.decoded_email;

        // Find the order
        const order = await orderCollection.findOne({
          _id: new ObjectId(orderId),
          "user.email": email,
        });

        if (!order) {
          return res.status(404).json({
            success: false,
            message: "Order not found or unauthorized",
          });
        }

        // Get tracking history for this order
        const trackingHistory = await trackingCollection
          .find({ orderId: new ObjectId(orderId) })
          .sort({ createdAt: 1 })
          .toArray();

        // Calculate estimated delivery
        const estimatedDelivery = new Date(order.createdAt);
        estimatedDelivery.setDate(estimatedDelivery.getDate() + 7); // Add 7 days for delivery

        // Get current location (latest tracking update)
        const currentLocation =
          trackingHistory.length > 0
            ? trackingHistory[trackingHistory.length - 1].location
            : null;

        res.status(200).json({
          success: true,
          data: {
            order: {
              ...order,
              estimatedDelivery,
              currentLocation,
            },
            trackingHistory,
            statistics: {
              totalSteps: trackingHistory.length,
              completedSteps: trackingHistory.filter(
                (t) => t.status === "completed"
              ).length,
              currentStep:
                trackingHistory.find((t) => t.status === "current") || null,
              pendingSteps: trackingHistory.filter(
                (t) => t.status === "pending"
              ).length,
            },
          },
          message: "Order tracking details fetched successfully",
        });
      } catch (error) {
        console.error("Error fetching tracking details:", error);
        res.status(500).json({
          success: false,
          message: "Failed to fetch order tracking information",
        });
      }
    });

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
          recentBookings: totalOrders,
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
