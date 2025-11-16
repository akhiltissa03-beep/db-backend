const UserLogin = require('../models/userlogin'); //Add New User
const AdminLogin = require('../models/adminlogin');
const Agreement = require('../models/agreement');
const User = require('../models/user');
const nodemailer = require('nodemailer'); // npm install nodemailer
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const cloudinary = require('../config/cloudinary')
const AssignmentDetails = require('../models/assingmentDetails.schema');
const { faker } = require('@faker-js/faker');


const sendConfirmationEmail = async(user, password) => {
    // console.log("user - line 13", user);
    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL, // Replace with your email
                pass: process.env.PASSWORD, // Replace with your email password
            },
        });

        const currentDate = new Date();
        const startingDate = currentDate.toLocaleDateString(); // Today's date
        const expiryDate = new Date(currentDate.getTime() + 5 * 24 * 60 * 60 * 1000); // 5 days later
        const formattedExpiryDate = expiryDate.toLocaleDateString();

        const mailOptions = {
            from: process.env.EMAIL,
            to: user.email,
            subject: 'Registration Confirmation - BLUECOM Data Entry Services',
            html: `
          <html>
            <head>
              <style>
                /* Add your custom CSS styles here */
              </style>
            </head>
            <body style="font-family: Arial, sans-serif;">
  
              <h2>Dear ${user.firstname} ${user.lastname},</h2>
  
              <p>Thank You For Choosing BLUECOM SERVICE. You Have Been Successfully Registered For The Work Of Data Entry Services.</p>
             <p>Were Excited To Provide You Our Uninterrupted Services.</p>
              <p>
              Kindly Confirm Your Registration Details Below :-
                <ul>
                    <li><strong>Name Of The Employee: </strong> ${user.firstname} ${user.lastname}</li>
                  <li><strong>Email: </strong> ${user.email}</li>
                  <!-- Add more registration details as needed -->
                </ul>
              </p>
  
              <p>
                <strong>Here's What You Need To Do Next..</strong>
                <a href="${process.env.SIDE_URL}/userlogin" target="_blank" rel="noopener noreferrer">Click here to get started</a>
              </p>
  
              <p>
                <strong>Account Information:</strong>
                <ul>
                  <li><strong>Username:</strong> ${user.email}</li>
                    <li><strong>Password:</strong> ${password} </li>
                    <!-- You may choose not to display the actual password -->
                </ul>
              </p>
  
              <p>
                <strong>Important Dates:</strong>
                <ul>
                <li><strong>Initial Starting Date:</strong> ${startingDate}</li>
                <li><strong>Account Expiry Date:</strong> ${formattedExpiryDate}</li>
               </ul>
              </p>
  
              <p>
                Please stay in touch with our customer service for any further support:
                <ul>
                  <li><strong>Customer Care:</strong>8983281770 (Mon - Sat, 10 AM - 5 PM)</li>
                  <li><strong>HelpLine No:</strong>8983281770</li>
                  
                  <li><strong>Email:</strong>zemixservice@gmail.com</li>
                </ul>
              </p>
  
              <p>
                You can also download your signed agreement <a href="https://zemixservices.netlify.app/employmentformdetails/${user._id}">here</a>.
              </p>
  
              <p>
                If you have any questions or need assistance, feel free to contact us. Thank you once again for choosing BLUECOM SERVICE.
              </p>
            </body>
          </html>
        `,
        };

        await transporter.sendMail(mailOptions);

        console.log('Confirmation email sent successfully');
    } catch (error) {
        console.error('Error sending confirmation email:', error);
    }
};


/******************************************************
 * @signup
 * @route http://localhost:8000/user/signup
 * @description Add new User in database
 * @returns User object
 ******************************************************/
const signup = async(req, res) => {
        // console.log(req.body);
        try {
            const { firstname, lastname, email, password, confirm_password } = req.body;

            if (password !== confirm_password) {
                return res.status(400).json({ error: 'Passwords do not match' });
            }

            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            const newUser = new UserLogin({
                firstname,
                lastname,
                email,
                password: hashedPassword,
            });
            const savedUser = await newUser.save();
            // Call the function to send confirmation email
            await sendConfirmationEmail(savedUser, password);
            res.status(201).json({ message: 'User added successfully', user: savedUser });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }
    //Generate JWT token
function generateAuthToken(user) {
    const token = jwt.sign({ _id: user._id, email: user.email, role: user.role }, 'yourSecretKey', { expiresIn: '1h' });
    return token; //Return Token
}

/******************************************************
 * @signin
 * @route http://localhost:8000/user/signin
 * @description User Login using this Route
 * @returns User object as Token
 ******************************************************/
const signin = async(req, res) => {
    try {
        const { email, password } = req.body;
        // Check if email and password are provided
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required.' });
        }
        // Find the user by email
        const user = await UserLogin.findOne({ email });
        // console.log(user);
        // Check if the user exists
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        // Check if the password is correct
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        // Generate and send the authentication token
        res.status(200).json({ message: 'Signin successful.', token: generateAuthToken(user), isStamp: user.isStamp });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};




/******************************************************
 * @adminsignin
 * @route http://localhost:8000/user/adminsignin
 * @description login for admin
 * @returns Message for success and Token 
 ******************************************************/
const adminsignin = async(req, res) => {
    try {
        const { username, password } = req.body;
        // Check if email and password are provided
        if (!username || !password) {
            return res.status(400).json({ message: 'Email and password are required.' });
        }
        // Find the user by email
        const user = await AdminLogin.findOne({ firstname: username, password: password });
        const role = user.role;
        // Check if the user exists
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        // Generate and send the authentication token
        res.status(200).json({ message: 'Signin successful.', role, token: generateadminToken(user) });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}




function generateadminToken(user) {
    const token = jwt.sign({ _id: user._id, email: user.email }, 'yourSecretKey', { expiresIn: '1h' });
    return token; //Return Token
}


/******************************************************
 * @add_terms
 * @route http://localhost:8000/user/add_terms
 * @description add Terms and Condition for Agreement
 * @returns Message for success
 ******************************************************/
const add_terms = async(req, res) => {
    try {
        const { email, startdate } = req.body;
        if (!req.files || !req.files['signature'] || !req.files['photo']) {
            return res.status(400).json({ error: 'Signature and photo files are required.' });
        }
        const { signature, photo } = req.files;
        const user = await User.findOne({ email: email });
        if (!user) {
            return res.status(404).json({ error: 'User not found.' });
        }
        const startDate = new Date(startdate);
        const endDate = new Date(startdate);
        startDate.toLocaleDateString('en-CA');
        endDate.setDate(endDate.getDate() + 4);
        const endDateFormatted = endDate.toLocaleDateString('en-CA');
        user.startDate = startdate;
        user.endDate = endDateFormatted;
        user.status = "Pending";
        await user.save();
        let signatureFile, photoFile;
        
        if (signature) {
            signatureFile = await cloudinary(signature[0].buffer);
        };
        if (photo) {
            photoFile = await cloudinary(photo[0].buffer);
        };
        const newAgreement = new Agreement({
            email,
            signature: signatureFile?.secure_url,
            photo: photoFile?.secure_url,
            startdate: startDate
        });
        const savedAgreement = await newAgreement.save();
        res.status(201).json(savedAgreement);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error', message: error.message });
    }
};

/******************************************************
 * @get_terms
 * @route http://localhost:8000/user/get_terms
 * @description Get Terms and Conditions for a specific user
 * @returns Agreement data for the specified user
 ******************************************************/
const get_terms = async(req, res) => {
    try {
        const allAgreements = await Agreement.find().sort({ _id: -1 });
        if (!allAgreements.length) {
            return res.status(404).json({ message: 'No agreements found' });
        }
        res.status(200).json({
            allAgreements,
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};

/******************************************************
 * @get_terms_by_id
 * @route http://localhost:8000/user/get_terms_by_id/id
 * @description Get Terms By ID
 * @returns Agreement Objrct
 ******************************************************/
const get_terms_by_id = async(req, res) => {
    try {
        const id = req.params.id;
        const results = await Agreement.findById(id);
        if (!results) {
            return res.status(404).json({ message: 'Not Found Any Record' });
        }
        const userEmail = results?.email;
        const userData = await User.findOne({email : userEmail});
        res.status(200).json({results,userData});
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Internal Server Erro!' });
    }
};

/******************************************************
 * @search_agreement
 * @route http://localhost:8000/user/search_agreement
 * @description Search Terms By Name
 * @returns Agreement Objrct
 ******************************************************/
const search_agreement = async(req, res) => {
    try {
        const { name } = req.body;
        const query = { name: { $regex: new RegExp(name, 'i') } };
        const results = await Agreement.find(query);
        if (name == "") {
            return res.status(404).json({ message: 'Please Enter Any Values for Search.' });
        }
        if (!results.length) {
            return res.status(404).json({ message: 'No agreements found with the specified name.' });
        }
        res.status(200).json(results);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
};


//change password
const changePassword = async (req, res) => {
    // console.log(req.body)
    try {
        // get new Password from body
        const { newPassword } = req.body;

        // find Admin by role 
        const admin = await AdminLogin.findOne({ role : "Admin"});
        // console.log(admin, "admin",newPassword);
         // Set new password
        admin.password = newPassword;
        await admin.save();

        res.status(200).json({message:"Password Successfully Changed"}); 

    } catch (error) {
        console.error(error)
        res.status(500).json({message:"Error changing Password"}); 
    }
}

// get todays registration
const getTodaysRegistrations = async (req, res) => {
    try {
        // Query users by status
        const start = new Date();
        // start.setHours(0,0,0,0);
        start.setUTCHours(0,0,0,0);

        const end = new Date(); 
        // end.setHours(23,59,59,999);
        end.setUTCHours(23,59,59,999);

        // console.log(start, end, "start end")
        const users = await User.aggregate([
            { 
              $match: {
                status: "Registered",  
                createdAt: {
                  $gte: start,
                  $lt: end 
                }
              }
            } 
          ]);
          
          res.json(users.length);
    
      } catch (err) {
        console.error(err);
        res.status(500).send('Server error'); 
      }
}


function generateRandomData() {
    return {
        name: faker.person.firstName(), // Generate full name
        address: faker.location.secondaryAddress(),
        pinCode: faker.location.zipCode(),
        jobFunctional: faker.person.jobTitle(), // Temporarily using deprecated method
        phone: faker.phone.number(),
        annualRevenue: faker.finance.amount() * 1000,
        cleanCode: faker.phone.imei()
    };
}

async function populateDatabase(req, res) {
    try {
        // Generate and insert 520 random data objects
        const dataObjects = Array.from({ length:520 }, generateRandomData);
        await AssignmentDetails.insertMany(dataObjects);
        // console.log('Data inserted successfully');
        res.send(200).json({"success": true})

    } catch (err) {
        console.error('Error inserting data:', err);
    } 
}

module.exports = { signup, signin, adminsignin, add_terms, get_terms, get_terms_by_id, search_agreement, changePassword,getTodaysRegistrations, populateDatabase };