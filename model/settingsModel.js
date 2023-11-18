const mongoose = require('mongoose');

const settingsSchema = new mongoose.Schema({
  fullName: String,
  email: String,
  address: String,
  city: String,
  state: String,
  zip: String,
  company: String,
  title: String,
  willSignForCompany: Boolean,
  isAttorney: Boolean,
});

const Settings = mongoose.model('Settings', settingsSchema);

module.exports = Settings;
