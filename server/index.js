const express = require("express");
const app = express();

let counter = 0;

app.get("/", (_, res) => {
  const currentTime = new Date().toLocaleTimeString();
  res.json({ currentTime, counter });
});

setInterval(() => {
  counter++;
}, 1000);

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
