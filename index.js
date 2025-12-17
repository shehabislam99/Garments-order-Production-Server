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

    //
    app.get("/users/:id", async (req, res) => {});

    //Role update in frontend
    app.patch(
      "/users/role/:id",
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

    //Role Suspend in frontend
    app.patch(
      "/users/suspend/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        await userCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              status: "suspended",
              suspendedAt: new Date(),
              suspendReason: req.body.suspendReason,
              suspendFeedback: req.body.suspendFeedback,
            },
          }
        );
        res.status(200).json({
          success: true,
          message: "User suspended successfully",
        });
      }
    );

    //Role status in frontend
    app.patch(
      "/users/status/:id",
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

    //  USER STATS IN FRONTEND (FULL DATABASE)
    app.get(
      "/manage-user/stats",
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

    // // Update the user/role endpoint to return just the role
    // app.post("/users/role/:email",verifyFBToken, async (req, res) => {
    //   const { email } = req.params;
    //   const query = { email: email };

    //   const user = await userCollection.findOne(query);

    //   if (!user) {
    //     return res.status(404).json({
    //       message: "User not found",
    //       role: "buyer",
    //     });
    //   }
    //   res.status(200).json({
    //     message: "User role found",
    //     role: user.role || "buyer",
    //     name: user.name,
    //     email: user.email,
    //   });
    // });

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
 app.get("/products/:id",verifyFBToken, async (req, res) => {
   const id = req.params.id;
   const query = { _id: new ObjectId(id) };
   const result = await productCollection.findOne(query);
   res.send(result);
 });
    // POST: add new product
    app.get("/products", async (req, res) => {
      const query = {};
      const { email, deliveryStatus } = req.query;

      // /products?email=''&
      if (email) {
        query.senderEmail = email;
      }

      if (deliveryStatus) {
        query.deliveryStatus = deliveryStatus;
      }

      const options = { sort: { createdAt: -1 } };

      const cursor = productCollection.find(query, options);
      const result = await cursor.toArray();
      res.send(result);
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

   

    app.get("/products/delivery-status/stats", async (req, res) => {
      const pipeline = [
        {
          $group: {
            _id: "$deliveryStatus",
            count: { $sum: 1 },
          },
        },
        {
          $project: {
            status: "$_id",
            count: 1,
            // _id: 0
          },
        },
      ];
      const result = await productCollection.aggregate(pipeline).toArray();
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

    // payment related apis
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

    // orders related apis
    app.get("/orders", async (req, res) => {
      const { status, district, workStatus } = req.query;
      const query = {};

      if (status) {
        query.status = status;
      }
      if (district) {
        query.district = district;
      }
      if (workStatus) {
        query.workStatus = workStatus;
      }

      const cursor = orderCollection.find(query);
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

    app.post("/orders", async (req, res) => {
      const order = req.body;
      order.status = "pending";
      order.createdAt = new Date();

      const result = await orderCollection.insertOne(order);
      res.send(result);
    });

    app.patch("/orders/:id", verifyFBToken, verifyAdmin, async (req, res) => {
      const status = req.body.status;
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          status: status,
          workStatus: "available",
        },
      };

      const result = await orderCollection.updateOne(query, updatedDoc);

      if (status === "approved") {
        const email = req.body.email;
        const userQuery = { email };
        const updateUser = {
          $set: {
            role: "manager",
          },
        };
        const userResult = await userCollection.updateOne(
          userQuery,
          updateUser
        );
      }

      res.send(result);
    });

    // tracking related apis
    app.get("/trackings/logs/:trackingId", async (req, res) => {
      const trackingId = req.params.trackingId;
      const query = { trackingId };
      const result = await trackingCollection.find(query).toArray();
      res.send(result);
    });

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
