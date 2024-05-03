const express = require("express");
const cors = require("cors");
const app = express();

app.use(cors());

let counter = 0;

app.get("/", (_, res) => {
  const currentTime = new Date().toLocaleTimeString();
  res.json({ currentTime, counter });
});

setInterval(() => {
  counter++;
}, 1000);

app.listen(5000, () => {
  console.log("Server is running on port 5000");
});
