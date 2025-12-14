const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const port = process.env.PORT || 3000;
app.use(express.json());
app.use(cors());

const { MongoClient, ServerApiVersion } = require("mongodb");
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
    const userProduct =db.collection("products");
    const userOrders = db.collection("orders")

    app.post("/user", async (req, res) => {
      try {
        const userInfo = req.body;
        userInfo.createdAt = new Date();

        const result = await userCollection.insertOne(userInfo);
        res.status(201).send({
          message: "User created successfully",
          inserted: true,
          result,
        });
      } catch (error) {
        console.error("User POST error:", error);
        res.status(500).send({ message: "Server error" });
      }
    });

    // Update the user/role endpoint to return just the role
    app.post("/user/role/:email", async (req, res) => {
      try {
        const { email } = req.params;
        const query = { email: email };

        const user = await userCollection.findOne(query);

        if (!user) {
          return res.status(404).json({
            message: "User not found",
            role: "buyer",
          });
        }
        res.status(200).json({
          message: "User role found",
          role: user.role || "buyer",
          name: user.name,
          email: user.email,
        });
      } catch (error) {
        console.error("Error fetching user role:", error);
        res.status(500).json({
          message: "Server error",
          role: "buyer",
        });
      }
    });

    // Add a GET endpoint for fetching role (better for AuthProvider)
    app.get("/user/role/:email", async (req, res) => {
      try {
        const { email } = req.params;
        const query = { email: email };
        const user = await userCollection.findOne(query);

        if (!user) {
          return res.status(200).json({
            role: "buyer", // Default role if not found
            exists: false,
          });
        }

        res.status(200).json({
          role: user.role || "buyer",
          exists: true,
          name: user.name,
        });
      } catch (error) {
        console.error("Error fetching user role:", error);
        res.status(500).json({
          role: "buyer", // Default on error
          exists: false,
        });
      }
    });
    // POST: add new product
    app.post("/products", async (req, res) => {
      try {
        const product = req.body;

        if (!product?.name || !product?.price) {
          return res.status(400).send({ message: "Missing required fields" });
        }

        product.createdAt = new Date();

        const result = await userProduct.insertOne(product);
        res.status(201).send(result);
      } catch (error) {
        res.status(500).send({ message: "Failed to add product" });
      }
    });

    // Get all products
    app.get("/products", async (req, res) => {
      try {
        const products = await userProduct.find().toArray();
        res.status(200).json(products);
      } catch (error) {
        console.error("Error fetching products:", error);
        res.status(500).json({ message: "Server error" });
      }
    });

    // Get all orders
    app.get("/orders", async (req, res) => {
      try {
        const orders = await userOrders.find().toArray();
        res.status(200).json(orders);
      } catch (error) {
        console.error("Error fetching orders:", error);
        res.status(500).json({ message: "Server error" });
      }
    });

    // Get all users (for admin panel)
    app.get("/users", async (req, res) => {
      try {
        const users = await userCollection.find().toArray();
        res.status(200).json(users);
      } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).json({ message: "Server error" });
      }
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
