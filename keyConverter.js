const fs = require("fs");
const jsonData = fs.readFileSync("./garments-production-tracker-e44ff38fd6f7.json","utf-8");

const base64String = Buffer.from(jsonData).toString("base64");
console.log(base64String);
