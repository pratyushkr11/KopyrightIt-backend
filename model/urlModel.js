
const mongoose = require("mongoose");
const { Schema } = mongoose;


const urlSchema = new Schema({
  fileUrl: String,
  imageUrl: String,
});


const UrlModel = mongoose.model("Url", urlSchema);

module.exports = UrlModel;
