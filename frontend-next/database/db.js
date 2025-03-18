const mongoose = require("mongoose");
const connectMongo = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to the MongoDB database!");
  } catch (error) {
    console.log("Error connecting to the MongoDB database:", error);
  }
};

export default connectMongo;
