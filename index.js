const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const app = express();
const cors = require("cors");
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());

const verifyJwt = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res
      .status(401)
      .send({ error: true, message: "Unauthorized access" });
  }
  // bearer token
  const token = authorization.split(" ")[1];
  jwt.verify(token, process.env.ACCESS_TOKEN, (err, decoded) => {
    if (err) {
      return res
        .status(403)
        .send({ error: true, message: "Unauthorized access" });
    }
    req.decoded = decoded;
    next();
  });
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.njyko.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    // all collection
    const allUsers = client.db("tastyBites").collection("users");
    const allMenu = client.db("tastyBites").collection("menu");
    const allReview = client.db("tastyBites").collection("review");
    const allCart = client.db("tastyBites").collection("carts");

    app.post("/jwt", (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN, {
        expiresIn: "1h",
      });
      res.send({ token });
    });

    // verify admin middleware. Use this after verifyJWT
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await allUsers.findOne(query);
      if (user?.role !== "admin") {
        return res
          .status(403)
          .send({ error: true, message: "Forbidded access" });
      }
      next();
    };

    // users related apis
    app.get("/users", verifyJwt, verifyAdmin, async (req, res) => {
      const result = await allUsers.find().toArray();
      res.send(result);
    });

    app.post("/users", async (req, res) => {
      const user = req.body;
      const query = { email: user?.email };
      const existingUser = await allUsers.findOne(query);
      if (existingUser) {
        return res.send({ message: "User already exist" });
      }
      const result = await allUsers.insertOne(user);
      res.send(result);
    });

    // security layer: verify jwt
    // email same
    // check admin
    app.get("/users/admin/:email", verifyJwt, async (req, res) => {
      const email = req.params.email;

      if (req.decoded.email !== email) {
        return res.send({ admin: false });
      }
      const query = { email: email };
      const user = await allUsers.findOne(query);
      const result = { admin: user?.role === "admin" };
      res.send(result);
    });

    app.patch("/users/admin/:id", async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          role: "admin",
        },
      };
      const result = await allUsers.updateOne(filter, updateDoc);
      res.send(result);
    });

    app.delete("/users/:id", async (req, res) => {
      const id = req?.params?.id;
      const query = { _id: new ObjectId(id) };
      const result = await allUsers.deleteOne(query);
      res.send(result);
    });

    // all menu items
    app.get("/menu", async (req, res) => {
      const result = await allMenu.find().toArray();
      res.send(result);
    });

    // all review
    app.get("/review", async (req, res) => {
      const result = await allReview.find().toArray();
      res.send(result);
    });

    // get cart
    app.get("/carts", verifyJwt, async (req, res) => {
      const email = req.query.email;
      if (!email) {
        res.send([]);
      }
      const decodedEmail = req.decoded.email;
      if (email !== decodedEmail) {
        return res
          .status(403)
          .send({ error: true, message: "Forbiddedn access" });
      }
      const query = { email: email };
      const result = await allCart.find(query).toArray();
      res.send(result);
    });

    // cart collection
    app.post("/carts", async (req, res) => {
      const item = req.body;
      const result = await allCart.insertOne(item);
      res.send(result);
    });

    // delete from cart
    app.delete("/carts/:id", async (req, res) => {
      const id = req.params?.id;
      const query = { _id: new ObjectId(id) };
      const result = await allCart.deleteOne(query);
      res.send(result);
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Welcome to our backend application!!");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
