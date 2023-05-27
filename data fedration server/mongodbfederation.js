const { MongoClient } = require("mongodb");
const url = "mongodb+srv://emseccomandcenter:TUXnEN09VNM1drh3@shodan.tqwfjzh.mongodb.net/test";
const databaseName = "test";
const client = new MongoClient(url);

async function dbConnect() 
{
  let result = await client.connect();
  db = result.db(databaseName);
  return db.collection("dataFederation");
}
module.exports = mongodbfederation;
module.exports = {dbConnect};