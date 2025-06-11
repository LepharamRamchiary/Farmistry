import dotenv from "dotenv";
import connectDB from "./db/index.js";
import { app } from "./app.js";

dotenv.config({
  path: "../.env",
});


connectDB()
  .then(() => {
    app.listen(process.env.PORT || 4000, () => {
      console.log(`Server is running at port: ${process.env.PORT}`);
    //   console.log(`Swagger docs available at http://localhost:${process.env.PORT}/api-docs`);
    });
  })
  .catch((err) => {
    console.log("MongoDB connection failed !!", err);
  });
