const express = require("express")
const mongoose = require('mongoose')
const cors = require("cors")
const Usermodel = require('./model/User')
const Formmodel = require("./model/LiteraryData")
const Settings = require('./model/settingsModel');
const nodemailer = require('nodemailer'); // Import Nodemailer
const bcrypt = require('bcrypt');
const saltRounds = 10;
const crypto = require('crypto');
const UrlModel = require("./model/urlModel"); // Import the UrlModel
require('dotenv').config();


const app = express()
app.use(express.json())
app.use(cors({
  origin: ["http://localhost:5173/", 'https://kopyrightit.onrender.com/']
}))

mongoose.connect(process.env.MONGO_DB)


// const multer = require('multer')

// Set up a Nodemailer transporter to send verification emails.
const transporter = nodemailer.createTransport({
  // Configure your email provider here
  service: process.env.MAIL_SERVICE,
  auth: {
    user: process.env.ROOT_GMAIL,
    pass: process.env.ROOT_PASS,
  },
});
// Store email verification tokens in MongoDB
const TokenSchema = new mongoose.Schema({
  email: String,
  token: String,
});
const Token = mongoose.model('Token', TokenSchema)


app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Find the user by their email
  Usermodel.findOne({ email: email })
    .then(user => {
      if (user) {
        const v = (user.isVerified)
        if (v) {
          // Compare the input password with the hashed password in the database
          // console.log("hdhfg")
          bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
              res.status(500).json({ error: "Internal server error" });
            } else if (result) {
              // Passwords match, so the user is authenticated
              const userId = user._id;
              res.status(200).json({ data: userId });
            } else {
              res.status(401).json({ error: "The password is incorrect" });
            }
          });
        } else {
          res.status(402).json({ error: "The user is not verified. Please verify your account first." });
        }
      } else {
        res.status(401).json({ error: "No record exists with that email" });
      }
    })
    .catch(err => {
      res.status(500).json({ error: "Internal server error" });
    });
});




app.post("/google-login", (req, res) => {
  const { name, email, password } = req.body;

  // Check if the user with the given email exists
  Usermodel.findOne({ email: email })
    .then(user => {
      if (user) {
        // User exists, check if the password is correct
        if (user.password === password) {
          // Assuming 'user._id' is the user's unique ID in the database
          const userId = user._id;
          res.status(200).json({ data: userId }); // Send user ID in response
        } else {
          res.status(401).json({ error: "The password is incorrect" });
        }
      } else {
        // User doesn't exist, create a new user
        Usermodel.create({ name: name, email: email, password: password, isVerified: true })
          .then(savedUser => {
            const userId = savedUser._id;
            res.status(200).json({ data: userId }); // Send user ID in response
          })
          .catch(err => {
            res.status(500).json({ error: "Error creating a new user" });
          });
      }
    })
    .catch(err => {
      res.status(500).json({ error: "Internal server error" });
    });
});



// Signup endpoint
app.post('/signup', (req, res) => {
  const { name, email, password } = req.body;

  // Usermodel.findOne({ email: email })
  // .then(user => {
  //   return res.status(401).json({ error: 'Error' });
  // })
  // Generate a unique verification token
  const token = crypto.randomBytes(20).toString('hex');

  // Hash the password using bcrypt
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ error: 'Error hashing the password' });
    }

    // Create a new user with the hashed password
    const user = new Usermodel({ name, email, password: hashedPassword, isVerified: false });
    user.save()
      .then(() => {
        // Store the verification token in MongoDB
        const verificationToken = new Token({ email, token });
        verificationToken.save()
          .then(() => {
            // Send a verification email
            const verificationLink = `https://kopyrightit-frontend.onrender.com/verify-email?email=${email}&token=${token}`;
            const mailOptions = {
              from: 'lahadeepkumar@gmail.com',
              to: email,
              subject: 'Email Verification',
              text: `Click this link to verify your email: ${verificationLink}`,
            };

            transporter.sendMail(mailOptions, (error, info) => {
              if (error) {
                console.error('Email could not be sent:', error);
              } else {
                // console.log('Email sent:', info.response);
              }
            });

            res.status(200).json({ message: 'User registered. Check your email for verification link.' });
          })
          .catch((err) => {
            res.status(500).json({ error: 'Error storing the verification token' });
          });
      })
      .catch((err) => {
        res.status(500).json({ error: 'Error creating the user' });
      });
  });
});

// Verification endpoint
app.post('/api/verify', async (req, res) => {
  const { email, token } = req.body;
  // console.log(email)
  // console.log(token)

  try {
    const foundToken = await Token.findOne({ email, token });
    // Update the user's "verified" status in the database

    if (foundToken) {
      // The email and token are valid
      // Delete the reset request from the database
      await Usermodel.findOneAndUpdate({ email }, { isVerified: true });
      await ResetRequest.deleteOne({ token });
      // console.log("hrllo")
      res.status(200).json({ message: 'Reset URL is valid' });
    } else {
      // Invalid or expired token
      res.status(401).json({ message: 'Reset URL is invalid' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error verifying reset URL' });
  }
});



const ResetRequest = mongoose.model('ResetRequest', {
  email: String,
  token: String,
});

// API to send a password reset email
app.post('/api/send-reset-email', async (req, res) => {
  const { email } = req.body;

  // Generate a random token with crypto
  const token = crypto.randomBytes(20).toString('hex');

  // Create a reset link with token
  const resetLink = `https://kopyrightit-frontend.onrender.com/forgotpassword?token=${token}&email=${email}`;

  const mailOptions = {
    from: 'lahadeepkumar@gmail.com',
    to: email,
    subject: 'Password Reset Request',
    text: `Click the following link to reset your password: ${resetLink}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    const resetRequest = new ResetRequest({ email, token });
    await resetRequest.save();
    res.status(200).json({ message: 'Password reset email sent successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error sending reset email' });
  }
});

// API to verify the reset URL
app.post('/api/verify-reset-url', async (req, res) => {
  const { token } = req.body;

  try {
    const resetRequest = await ResetRequest.findOne({ token });

    if (resetRequest) {
      // The email and token are valid
      // Delete the reset request from the database
      await ResetRequest.deleteOne({ token });
      res.status(200).json({ message: 'Reset URL is valid' });
    } else {
      // Invalid or expired token
      res.status(401).json({ message: 'Reset URL is invalid' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error verifying reset URL' });
  }
});


// API to change the password
app.post('/api/change-password', async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    // Assuming you have a User model
    const user = await Usermodel.findOne({ email });

    if (user) {

      // Hash the new password
      const hashedPassword = await bcrypt.hash(newPassword, 10); // 10 is the salt rounds

      // Update the user's password
      user.password = hashedPassword;
      await user.save();

      res.status(200).json({ message: 'Password changed successfully' });
    } else {
      res.status(401).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error changing password' });
  }
});





app.post("/form", (req, res) => {
  Formmodel.create(req.body)
    .then(literaryforms => res.json(literaryforms))
    .catch(err => res.json(err))
})


app.get('/getforms', (req, res) => {
  Formmodel.find()
    .then(literaryforms => res.json(literaryforms))
    .catch(err => res.json(err))
})

app.get('/getformsu', (req, res) => {
  const userId = req.query.userId; // Get the user ID from the query parameters

  if (!userId) {
    return res.status(400).json({ message: 'User ID is required' });
  }

  Formmodel.find({ userId: userId }) // Assuming 'userId' is the field in your schema that stores the user ID
    .then((literaryforms) => {
      res.json(literaryforms);
    })
    .catch((err) => {
      res.status(500).json({ error: err.message });
    });
});


app.post('/api/settings', async (req, res) => {
  try {
    const newSettings = new Settings(req.body);
    await newSettings.save();
    res.status(201).json({ message: 'Settings saved successfully' });
  } catch (err) {
    console.error('Error saving settings:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Create a route to handle GET requests to fetch the user's email
app.get('/api/user/email/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;

    // Find the user by userId in the "users" collection
    const user = await Usermodel.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ email: user.email });
  } catch (err) {
    console.error('Error fetching user email:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});



// Create a route to handle sending emails
app.post('/api/sendEmail', async (req, res) => {
  try {
    const { fullName, email, issue } = req.body;
    // Find the user by email in the "users" collection
    const user = await Usermodel.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Create a Nodemailer transporter
    const transporter = nodemailer.createTransport({
      service: process.env.MAIL_SERVICE,
      auth: {
        user: process.env.ROOT_GMAIL,
        // pass: 'ysub vcfe ytwi vwbb', 
        pass: process.env.ROOT_PASS,
      },
    });

    // Email configuration
    const mailOptionsToUser = {
      from: 'lahadeepkumar@gmail.com',
      to: email, // User's email address
      subject: 'Regarding Your Copyright Query',
      text: `Dear ${fullName},\n\nThank you for reaching out regarding your copyright query. We will get back to you shortly.`,
    };

    // List of recipient email addresses for multiple sender
    // const recipientEmails = ['lahadeepkumar@gmail.com', 'anotheremail@example.com', 'yetanotheremail@example.com'];


    const mailOptionsToSender = {
      from: 'lahadeepkumar@gmail.com',
      to: 'lahadeepkumar@gmail.com', // Your email address
      // to: recipientEmails.join(','), // Join the email addresses with commas for multiple sender
      subject: 'User Copyright Query',
      text: `Full Name: ${fullName}\nEmail: ${email}\nIssue: ${issue}`,
    };

    // Send the emails
    transporter.sendMail(mailOptionsToUser, (errorToUser, infoToUser) => {
      if (errorToUser) {
        console.error('Error sending email to user:', errorToUser);
        // Handle the error for the user's email separately if needed
      } else {
        // console.log('Email sent to user:', infoToUser.response);
      }
    });

    transporter.sendMail(mailOptionsToSender, (errorToSender, infoToSender) => {
      if (errorToSender) {
        // console.error('Error sending email to sender:', errorToSender);
        res.status(500).json({ message: 'Error sending email to sender' });
      } else {
        // console.log('Email sent to sender:', infoToSender.response);
        res.json({ message: 'Email sent successfully' });
      }
    });
  } catch (err) {
    console.error('Error processing email:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});



// aws s3 buckets links 
const { S3Client, GetObjectCommand, PutObjectCommand } = require("@aws-sdk/client-s3")
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner")

const s3Client = new S3Client({
  region: "ap-south-1",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEYID,
    secretAccessKey: process.env.AWS_SECRET_KEYID
  },
})

// getting the url and saving it but saving not work url expire 
// so generate when admin wants in admin page update it or rewrite it
app.post("/saveUrls", async (req, res) => {
  try {
    const { fileKey, imageKey } = req.body;

    if (!fileKey || !imageKey) {
      return res.status(400).send("Both fileKey and imageKey are required.");
    }
    const fileUrl = await getObjectURL("upload/" + fileKey);
    const imageUrl = await getObjectURL("upload/" + imageKey);
    // console.log(fileUrl)
    // console.log(imageUrl)

    // Create a new record with the fileUrl and imageUrl
    const newUrl = new UrlModel({
      fileUrl,
      imageUrl,
    });

    // Save the new record to the MongoDB database
    const savedRecord = await newUrl.save();

    // Respond with the ID of the saved record
    res.json({ id: savedRecord._id });
  } catch (error) {
    console.error("Error saving data:", error);
    res.status(500).send("Error saving data");
  }
});

async function getObjectURL(key) {
  const command = new GetObjectCommand({
    Bucket: "copyright-app-uploader",
    Key: key,
  });
  const url = await getSignedUrl(s3Client, command);
  return url;
}



// get the url to upload the file or image it working fine
app.get('/getUploadUrl', async (req, res) => {
  try {
    const filename = `image-${Date.now()}.jpeg`; // Modify the filename as needed
    const contentType = 'image/jpeg'; // Modify the content type as needed

    const command = new PutObjectCommand({
      Bucket: "copyright-app-uploader",
      Key: `upload/${filename}`,
      ContentType: contentType,
    });

    const url = await getSignedUrl(s3Client, command);

    // res.json({ url });
    // console.log("hello")

    res.json({ url, key: filename });
  } catch (error) {
    console.error('Error generating S3 URL:', error);
    res.status(500).json({ error: 'Error generating S3 URL' });
  }
});


// getting username and email for dashboard
app.get('/api/user/:userId', async (req, res) => {
  try {
    const _id = req.params.userId;

    const user = await Usermodel.findById(_id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      name: user.name,
      email: user.email,
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching user data' });
  }
});

app.listen(3001, () => {
  console.log("server is running")
})