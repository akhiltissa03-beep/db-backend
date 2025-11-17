const User = require('../models/user');
const new_Assignment = require("../models/assignment");
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');
const mongoose = require('mongoose');
const { PDFDocument } = require('pdf-lib');
const blobStream = require('blob-stream');
const { createObjectCsvWriter } = require('csv-writer');

const Agreement = require("../models/agreement");
const Adminlogin = require('../models/adminlogin');
const Employee = require("../models/employee")

const generateRandomPassword = () => {
    const randomPassword = Math.floor(Math.random() * 9000000000) + 1000000000;
    return randomPassword.toString();;
};

const transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD,
  },
});
//Send Mail For Registration Confirmation
const sendConfirmationEmail = async(email, password, name) => {
    try {
        console.log("username and password",process.env.EMAIL,process.env.PASSWORD)
        const expiryTimestamp = new Date().getTime() + 48 * 60 * 60 * 1000;
        const encodedExpiryTimestamp = encodeURIComponent(expiryTimestamp.toString());
        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Registration Confirmation - Alphabet Services',
            html: `
            <html>
            <head>
              <style>
                body {
                  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                  line-height: 1.6;
                  color: black;
                  margin: 0;
                  padding: 0;
                }
                .container {
                  max-width: 600px;
                  margin: 0 auto;
                }
                .header {
                  background-color: #007bff;
                  padding: 20px;
                  text-align: center;
                  color: #fff;
                }
                .content {
                  padding: 20px;
                  border: 1px solid #ddd;
                  border-radius: 5px;
                  background-color: #fff;
                }
                h2 {
                  color: white;
                }
                strong {
                  color: #007bff;
                }
                a {
                  color: blue;
                }
                p {
                  margin: 0 0 15px;
                }
                .link{
                    color:blue;
                }
              </style>
            </head>
            <body>
              <div class="container">
                <div class="header">
                  <h2 >Alphabet Services</h2>
                </div>
                <div class="content">
                  <p>
                    <span>Dear ${name},</span>
                  </p>
                  <p>
                    Thank you for choosing Alphabet Services. You have been successfully registered for the Data Entry Services.
                  </p>
                  <p>
                  <p class="link"> Submit Your Agreement Form </p>
                    <a href="${process.env.SIDE_URL}/employmentform"> here</a>
                  </p>
                  <p>
                    <p>Company Information:</p>
                    <p>Helpline mail id:</p> helplinezxservicewww@gmail.com<br>
                    <p>Helpline No : 8983281770 </a>
                   </p>
                  <!-- Remaining content... -->
                </div>
              </div>
            </body>
          </html>
            `,
        };
        const mailsent = await transporter.sendMail(mailOptions);
        console.log('Confirmation email sent successfully', mailsent);
        return mailsent;
    } catch (error) {
        console.error('Error sending confirmation email:', error);
    }
};

/******************************************************
 * @add_user
 * @route http://localhost:8000/user/add_user
 * @description Save New User in Database
 * @returns User object
 ******************************************************/
const add_user = async(req, res) => {
    try {
        const { name, email, mobile, address, plan, caller } = req.body;
        console.log("req.body...",req.body)
        if (!name || !email || !mobile || !address || !plan || !caller) {
            return res.status(400).json({ message: 'All fields are required.' });
        }
        const existsUser = await User.findOne({
            email: email
        });
        if (existsUser) {
            return res.status(400).json({ message: 'Email Already Exists...' });
        }
        // Generate a random password
        const password = generateRandomPassword();
        const callerName = await Employee.findOne({id:caller})
        console.log(callerName,"callername")
        const newUser = new User({
            name,
            email,
            mobile,
            address,
            plan,
            caller,
            status: 'Registered',
            password,
            totalAssignment: 520,
            pendingAssignment: 520,
        });
        const savedUser = await newUser.save();
        await sendConfirmationEmail(email, password, name);
        res.status(201).json({ message: 'User added successfully', user: savedUser });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};

/******************************************************
 * @userlogin
 * @route http://localhost:8000/user/userlogin
 * @description find user for login
 * @returns success message for user login
 ******************************************************/
const userlogin = async(req, res) => {
    try {
        const { email, password } = req.body;
        // Check user login credentials
        const user = await User.findOne({ email, password });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        // if (user.status === 'Freeze') {
        //     return res.status(403).json({ message: 'User account is frozen. Please contact support.' });
        // }
        // Check user access time   
        const currentDate = new Date();
        const userEndDate = new Date(user.endDate);
        const isWithin12Hours = new Date(userEndDate.getTime() + 12 * 60 * 60 * 1000);
        // console.log("Dates are",currentDate,userEndDate,isWithin12Hours);
        // console.log("Dates are",userEndDate < currentDate);
        // console.log("Dates are",userEndDate >
        //  currentDate);

        if (userEndDate < currentDate) {
            // Freeze the user's account
            user.status = 'Freeze';
            await user.save();
            return res.status(200).json({ message: 'User status updated to Freeze', status: user.status });
        }

        if (userEndDate > currentDate) {
            const timeDifference = userEndDate.getTime() - currentDate.getTime();
            const days = Math.floor(timeDifference / (1000 * 3600 * 24));
            const role = user.role;
            const id = user._id;
            // console.log(id);
            return res.status(200).json({ message: 'Login success..', role, days, token: generateuserToken(user), id });
        } 
        // else {
        //     if (isWithin12Hours > currentDate) {
        //         user.status = 'Freeze';
        //         await user.save();
        //         const status = user.status;
        //         return res.status(200).json({ message: 'User status updated to Freeze', status });

        //     } else {
        //         return res.status(404).json({ message: 'QUC Failed' });
        //     }

        // }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server error' });
    }
};


async function updateCallerNames() {
    try {
      const users = await User.find(); // Fetch all users
  
      for (const user of users) {
        let employeeName; // Variable to hold the employee name
  
        // Handle String Caller Values
        if (typeof user.caller === 'string') {
          const employee = await Employee.findOne({ _id: user.caller });
          if (employee) {
            employeeName = employee.name;
          } else {
            console.warn('Employee not found:', user.caller); // Handle missing employees
          }
        }
  
        // Handle Reference ID Caller Values
        else if (user.caller instanceof mongoose.Schema.Types.ObjectId) {
          const employee = await Employee.findById(user.caller); // Use findById for reference IDs
          if (employee) {
            employeeName = employee.name;
          } else {
            console.warn('Employee not found:', user.caller); // Handle missing employees
          }
        }
  
        // Update User Document (if employee name found)
        if (employeeName) {
          user.callerName = employeeName; // Update optional field (if added)
          user.caller = employeeName; // Update caller field with name
          await user.save();
        }
      }
  
    //   console.log('Updated documents:', users.length);
    } catch (err) {
      console.error('Error updating documents:', err);
    } finally {
      mongoose.connection.close(); // Close connection after operation
    }
}
  

 
// const userlogin = async (req, res) => {
//     try {
//         const { email, password } = req.body;
        
//         // Check user login credentials
//         const user = await User.findOne({ email, password });
        
//         if (!user) {
//             return res.status(404).json({ message: 'User not found' });
//         }

//         // Check if the user's end date has passed
//         const currentDate = new Date();
//         const userEndDate = new Date(user.endDate);
        
//         if (userEndDate < currentDate) {
//             // Freeze the user's account
//             user.status = 'Freeze';
//             await user.save();
//             return res.status(200).json({ message: 'User status updated to Freeze', status: user.status });
//         }

//         // Check user access time
//         const isWithin12Hours = new Date(userEndDate.getTime() - 12 * 60 * 60 * 1000);
        
//         if (isWithin12Hours < currentDate) {
//             // Return login success
//             const timeDifference = userEndDate.getTime() - currentDate.getTime();
//             const days = Math.floor(timeDifference / (1000 * 3600 * 24));
//             const role = user.role;
//             const id = user._id;
//             return res.status(200).json({ message: 'Login success..', role, days, token: generateuserToken(user), id });
//         } else {
//             // Return login failed
//             return res.status(404).json({ message: 'QUC Failed' });
//         }
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ error: 'Internal Server error' });
//     }
// };


//Generate Token
function generateuserToken(user) {
    const token = jwt.sign({ _id: user._id, email: user.email }, 'yourSecretKey', { expiresIn: '1h' });
    return token; //Return Token
}


/******************************************************
 * @forgot_password
 * @route http://localhost:8000/user/forgot_password
 * @description Verify User and then send otp via mail
 * @returns Message for Success
 ******************************************************/
const forgot_password = async (req, res) => {
    const { email } = req.body;
    try {
        const user = await Adminlogin.findOne({ email });
        if (user) {
            const otp = generateOTP();
            user.passwordResetOTP = otp;
            try {
                const updatedUser = await user.save(); // Fix: Change Adminlogin.save() to user.save()
                // Send OTP to user's email
                await sendOTPEmail(user.email, otp);
                res.json({ message: 'User verified successfully, and OTP sent via mail.', user_id: user._id });
            } catch (saveError) {
                console.error('Error saving user:', saveError);
                res.status(500).json({ error: 'Error saving user data.' });
            }
        } else {
            res.status(401).json({ error: 'Invalid credentials.' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}


//Generate OTP
function generateOTP() {
    const OTP_LENGTH = 6;
    const min = Math.pow(10, OTP_LENGTH - 1);
    const max = Math.pow(10, OTP_LENGTH) - 1;
    return Math.floor(min + Math.random() * (max - min + 1)).toString().padStart(OTP_LENGTH, '0');
}

//send OTP via email
async function sendOTPEmail(email, otp) {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL,
            pass: process.env.PASSWORD,
        },
    });
    const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: 'Password Reset OTP',
        html: `
            <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; background-color: #f4f4f4; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                <h2 style="color: #007bff; text-align: center;">Alphabet Services - Password Reset OTP</h2>
                <p style="font-size: 16px; text-align: justify;">Dear User,</p>
                <p style="font-size: 16px; text-align: justify;">Your OTP for password reset is: <strong>${otp}</strong></p>
                <p style="font-size: 16px; text-align: justify;">Please use this OTP to reset your password. If you didn't request this, please ignore this email.</p>
                <hr style="border: 1px solid #ddd; margin: 15px 0;">
                <p style="font-size: 16px; text-align: justify;">Thank you for choosing Alphabet Services.</p>
                <p style="font-size: 16px; text-align: justify;">Best Regards,<br/>Alphabet Services Team</p>
            </div>
        `,
    };
    await transporter.sendMail(mailOptions);
}


/******************************************************
 * @verify_otp
 * @route http://localhost:8000/user/verify_otp
 * @description Verify OTP 
 * @returns Message for Success
 ******************************************************/
const verify_otp = async(req, res) => {
    const { passwordResetOTP } = req.body; // Destructure the passwordResetOTP from req.body
    try {
        const user = await Adminlogin.findOne({ passwordResetOTP }); // Corrected the query
        if (user) {
            const id = user._id;
            res.status(200).json({ message: 'OTP verified successfully', id });
        } else {
            res.status(401).json({ message: 'Invalid OTP' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}

/******************************************************
 * @submit_password
 * @route http://localhost:8000/user/submit_password/:id
 * @description Save New Password in Database Using ID
 * @returns Message for Success
 ******************************************************/
const submit_password = async(req, res) => {
    const { newPassword, confirmPassword } = req.body;
    const userId = req.params.id; // Assuming you have the correct parameter name
    // console.log(userId);
    try {
        // Find the user by ID
        const user = await Adminlogin.findById(userId);
        // Check if the user exists
        // console.log(user);
        if (newPassword == "" || confirmPassword == "") {
            return res.status(400).json({ error: 'Please Enter Any Values' });
        }
        if (user) {
            // Check if newPassword and confirmPassword match
            if (newPassword !== confirmPassword) {
                return res.status(400).json({ error: 'Password and Confirm Password do not match.' });
            }
            // Update password and reset OTP
            user.password = newPassword;
            // user.passwordResetOTP = undefined;
            // Save changes to the database
            await user.save();
            // Respond with success message
            return res.status(200).json({ message: 'Password Reset Successfully.' });
        } else {
            // If user is not found, respond with an error
            return res.status(401).json({ error: 'Invalid credentials.' });
        }
    } catch (error) {
        // Handle unexpected errors
        console.error(error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
};

/******************************************************
 * @get_all_user
 * @route http://localhost:8000/user/get_all_user
 * @description Get all Users from Database
 * @returns Array of User objects
 ******************************************************/
// const get_all_user = async(req, res) => {
//     try {
//         const defaultPage = 1;
//         const defaultLimit = 10;
//         // Get page number and limit from query parameters (use default values if not provided)
//         const { page = defaultPage, limit = defaultLimit } = req.query;
//         const pageNumber = parseInt(page, 10);
//         const limitNumber = parseInt(limit, 10);
//         if (isNaN(pageNumber) || isNaN(limitNumber) || pageNumber < 1 || limitNumber < 1) {
//             return res.status(400).json({ message: 'Invalid page or limit values.' });
//         }
//         // Get the total number of users 
//         const totalUsers = await User.countDocuments();
//         // Calculate the total number of pages
//         const totalPages = Math.ceil(totalUsers / limitNumber);
//         // Ensure the requested page is within bounds
//         if (pageNumber > totalPages) {
//             return res.status(400).json({ message: 'Invalid page number.' });
//         }
//         // Calculate the skip value based on the page number and limit
//         const skip = (pageNumber - 1) * limitNumber;
//         const allUser = await User.find().sort({ _id: -1 }).skip(skip).limit(limitNumber);
//         res.status(200).json({
//             allUser,
//             currentPage: pageNumber,
//             totalPages,
//             totalUsers,
//         });
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ error: 'Internal Server Error' });
//     }
// }

const get_all_user = async (req, res) => {
    try {
      // Remove pagination logic
      const allUsers = await User.find().sort({ _id: -1 }); // Fetch all users, sorted by ID descending
  
      res.status(200).json({
        allUsers,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  };

/******************************************************
 * @getuser_by_status
 * @route http://localhost:8000/user/getuser_by_status
 * @description Find users by status From Database
 * @returns Array of User objects
 ******************************************************/
const getuser_by_status = async(req, res) => {
    try {
        const status = req.body.status;
        const users = await User.find({ status });
        res.status(200).json({ User: users });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}

/******************************************************
 * @update_user_status
 * @route http://localhost:8000/user/update_user_status/:id
 * @description Update user status by admin Using ID
 * @returns Success message
 ******************************************************/
const update_user_status = async(req, res) => {
    try {
        const userId = req.params.id; // Extract user ID from the URL parameter
        const { status } = req.body; // Destructure the 'status' from req.body
        if (!userId) {
            return res.status(400).json({ message: 'User ID is required.' });
        }
        const updatedUser = await User.findByIdAndUpdate(
            userId, { status }, { new: true }
        );
        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found.' });
        }
        res.status(200).json({ message: 'Status updated successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}


/******************************************************
 * @delete_user
 * @route http://localhost:8000/user/delete_user
 * @description Delete Use By ID 
 * @returns Message for Success
 ******************************************************/
const delete_user = async(req, res) => {
    try {
        const userId = req.params.id;
        // Check if userId is provided
        if (!userId) {
            return res.status(400).json({ message: 'User ID is required.' });
        }
        const result = await User.deleteOne({ _id: userId });
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }
        res.status(200).json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}


/******************************************************
 * @edit_user
 * @route http://localhost:8000/user/edit_user/:id
 * @description Update User Details by ID
 * @returns Updated User object
 ******************************************************/
const edit_user = async(req, res) => {
    try {
        const userId = req.params.id; // Extract user ID from the URL parameter
        const { name, email, mobile, address, plan, caller } = req.body;
        if (!userId) {
            return res.status(400).json({ message: 'User ID is required.' });
        }
        const updatedUser = await User.findByIdAndUpdate(
            userId, {
                name,
                email,
                mobile,
                address,
                plan,
                caller,
            }, { new: true }
        );
        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found.' });
        }
        res.status(200).json({ message: 'User updated successfully', user: updatedUser });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}

/******************************************************
 * @search_users
 * @route http://localhost:8000/user/search_users
 * @description Search Users by startDate and endDate
 * @returns Array of User objects
 ******************************************************/
const search_users = async(req, res) => {
    try {
        const { startDate, endDate } = req.body;
        // Check if both startDate and endDate are provided
        if (!startDate || !endDate) {
            return res.status(400).json({ message: 'Both startDate and endDate are required for searching.' });
        }
        // Convert startDate and endDate to Date objects
        const startDateObj = new Date(startDate);
        const endDateObj = new Date(endDate);
        // Add 1 day to the endDate to include the whole day
        endDateObj.setDate(endDateObj.getDate() + 1);
        // Search for users between startDate and endDate
        const users = await User.find({
            startDate: { $gte: startDateObj, $lt: endDateObj },
        });
        res.status(200).json({ users });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}

/******************************************************
 * @getuser_by_id
 * @route http://localhost:8000/user/getuser_by_id/:id
 * @description Get User by ID
 * @returns User object
 ******************************************************/
const getuser_by_id = async(req, res) => {
    try {
        const getid = req.params.id;
        const user = await User.findById(getid); // Corrected this line by using findById
        res.status(200).json({ User: user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}


/******************************************************
 * @search_user_by_name
 * @route http://localhost:8000/user/search_user_by_name
 * @description Search user by it name
 * @returns User object
 ******************************************************/
// const search_user_by_name = async(req, res) => {
//     try {
//         const { status } = req.query;
//         const { name } = req.body;
//         // Check if name is provided
//         if (name == "") {
//             return res.status(404).json({ message: 'Please Enter Any Values for Search.' });
//         }
//         if (!name) {
//             return res.status(400).json({ message: 'Name is required for searching.' });
//         }
//         // Search for users by name and optional status
//         const query = { name: { $regex: new RegExp(name, 'i') } };
//         if (status) {
//             query.status = status;
//         }
//         const users = await User.find(query);
//         res.status(200).json({ users });
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ error: 'Internal Server Error' });
//     }
// };

const search_user_by_name = async (req, res) => {
    try {
        const { status } = req.query;
        const { name } = req.body;

        // Check if name is provided
        if (!name) {
            return res.status(400).json({ message: 'Name is required for searching.' });
        }

        // Construct query to search across name, email, and mobile fields
        const query = {
            $or: [
                { name: { $regex: new RegExp(name, 'i') } },
                { email: { $regex: new RegExp(name, 'i') } },
                { mobile: { $regex: new RegExp(name, 'i') } }
            ]
        };
        if (status) {
            query.status = status;
        }

        // Search for users using the constructed query
        const users = await User.find(query);

        res.status(200).json({ users });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};


/******************************************************
 * @user_pagination
 * @route http://localhost:8000/user/user_pagination
 * @description get User by Pagination
 * @returns User object
 ******************************************************/
const user_pagination = async(req, res) => {
    try {
        const { status } = req.query; // Get status parameter for filtering
    
        // Build the query object with the condition based on the status parameter
        const query = status ? { status: status } : {}; // Empty query if no status provided
    
        // Fetch all users based on the condition (no pagination)
        const users = await User.find(query).sort({ _id: -1 });
        const totalUsers = await User.countDocuments(query);
        res.status(200).json({
          totalUsers,
          users,
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
};


/******************************************************
 * @sendUserInfo
 * @route http://localhost:8000/user/sendUserInfo/id
 * @description Send User mail
 * @returns message
 ******************************************************/
const sendUserInfo = async(req, res) => {
    try {
        const { userId } = req.params;
        // console.log(userId, "userId");
        const user = await User.findById({ _id: userId });
        const aggrUserId = await Agreement.findOne({ email: user.email });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        user.status = "Success";
        await user.save();
        const formatDate = (date) => new Date(date).toLocaleDateString('en-US', { year: 'numeric', month: '2-digit', day: '2-digit' });
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                type: 'login',
                user: process.env.EMAIL, // Replace with your email
                pass: process.env.PASSWORD, // Replace with your email password
            },
        });

        const mailOptions = {
            from: process.env.EMAIL,
            to: user.email,
            subject: 'Welcome to Alphabet Services',
            html: `
            <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; background-color: #f4f4f4; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
              <h2 style="color: #007bff; text-align: center;">Welcome to Alphabet Services</h2>
              <p style="font-size: 16px; text-align: justify;">Dear ${user.name},</p>
              <p style="font-size: 16px; text-align: justify;">Thank you for choosing Alphabet Services. You have been successfully registered for the work of Data Entry Services.</p>
              <p style="font-size: 16px; text-align: justify;">We're excited to provide you with our uninterrupted services.</p>
              <hr style="border: 1px solid #ddd; margin: 15px 0;">
              
              <p style="font-size: 16px;"><strong>Registration Details:</strong></p>
              <ul style="list-style: none; padding: 0; margin: 0;">
                <li style="font-size: 16px;"><strong>Name of the Employee:</strong> ${user.name}</li>
                <li style="font-size: 16px;"><strong>Email:</strong> ${user.email}</li>
                <li style="font-size: 16px;"><strong>Phone:</strong> ${user.mobile}</li>
              </ul>
              <p style="font-size: 16px; text-align: justify;">Here's what you need to do next:</p>
              <p style="font-size: 16px;"><a href="${process.env.SIDE_URL}/userlogin" target="_blank" style="color: #007bff; text-decoration: none; display: inline-block; margin-top: 10px; padding: 10px 20px; background-color: #007bff; color: #fff; border-radius: 5px; text-align: center;">Click here to get started</a></p>
              <p style="font-size: 16px;"><strong>Username:</strong> ${user.email}</p>
              <p style="font-size: 16px;"><strong>Password:</strong> ${user.password}</p>
              <p style="font-size: 16px;"><strong>Initial Starting Date:</strong> ${formatDate(user.startDate)} | <strong>Account Expiry Date:</strong> ${formatDate(user.endDate)}</p>
              <hr style="border: 1px solid #ddd; margin: 15px 0;">
              
              <p style="font-size: 16px; text-align: justify;">Stay in touch with our customer service for more support.</p>
              <p style="font-size: 16px;"><strong>Customer Care:</strong> 8983281770 (10 AM - 5 PM, Mon - Sat)</p>
              <p style="font-size: 16px;">Mail us anytime: <a href="mailto:helplinezxservicewww@gmail.com" style="color: #007bff; text-decoration: none;">helplinezxservicewww@gmail.com</a></p>
              <p style="font-size: 16px;">You can download your signed agreement <a href="https://zemixservices.netlify.app/employmentformdetails/${aggrUserId ._id}" style="color: #007bff; text-decoration: none;">here</a></p>
              <p style="font-size: 16px;"><strong>Company Information:</strong><br>
              <strong>Helpline mail id:</strong> helplinezxservicewww@gmail.com<br>
              </p>
            </div>
          `,
        };
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error(error);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            // console.log(`Email sent: ${info.response}`);
            res.status(200).json({ message: 'Email sent successfully' });
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};


/******************************************************
 * @update_endDate
 * @route http://localhost:8000/user/update_endDate/id
 * @description Get Amount from User and Update endDate and Status
 * @returns Update Date and Status
 ******************************************************/
const update_endDate = async(req, res) => {
    try {
        const userId = req.params.id;
        const amount = req.body.amount;
        if (!amount || isNaN(amount)) {
            return res.status(400).json({ error: 'Invalid amount provided.' });
        }
        // Find the user by ID
        const user = await User.findById(userId);
        // Check if the user exists
        if (!user) {
            c
            return res.status(404).json({ error: 'User not found.' });
        }
        const today = new Date().toLocaleDateString('en-CA'); // Adjust locale if necessary
        const endDate = new Date();
        endDate.setDate(endDate.getDate() + 5);
        const endDateFormatted = endDate.toLocaleDateString('en-CA'); // Adjust locale if necessary
        // Update user fields
        user.startDate = today;
        user.endDate = endDateFormatted;
        user.status = 'Success';
        user.amount.push(amount);
        // Save user
        await user.save();
        res.status(200).json({ message: 'User details updated successfully.', user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error.' });
    }
};


/******************************************************
 * @recovery_user
 * @route http://localhost:8000/user/recovery_user
 * @description get all recovery users
 * @returns User object
 ******************************************************/
const recovery_user = async(req, res) => {
    try {
        const defaultPage = 1;
        const defaultLimit = 10;
        // Get page number and limit from query parameters
        const { page = defaultPage, limit = defaultLimit } = req.query;
        const pageNumber = parseInt(page, 10);
        const limitNumber = parseInt(limit, 10);
        if (isNaN(pageNumber) || isNaN(limitNumber) || pageNumber < 1 || limitNumber < 1) {
            return res.status(400).json({ message: 'Invalid page or limit values.' });
        }
        // Get the total number of users 
        const totalUsers = await User.countDocuments({ 'amount': { $exists: true, $ne: [] }, });
        // Calculate the total number of pages
        const totalPages = Math.ceil(totalUsers / limitNumber);
        // Ensure the requested page is within bounds
        if (pageNumber > totalPages) {
            return res.status(400).json({ message: 'Invalid page number.' });
        }
        // Calculate the skip value based on the page number and limit
        const skip = (pageNumber - 1) * limitNumber;
        const users = await User.find({
            'amount': { $exists: true, $ne: [] },
        }).sort({ _id: -1 }).skip(skip).limit(limitNumber);

        res.status(200).json({
            users,
            currentPage: pageNumber,
            totalPages,
            totalUsers,
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error.' });
    }
};

/******************************************************
 * @search_recovery
 * @route http://localhost:8000/user/search_recovery
 * @description Search user by it covery
 * @returns User object
 ******************************************************/
const search_user_recovery = async(req, res) => {
    try {
        const { name } = req.body;
        // Check if name is provided
        if (name == "") {
            return res.status(404).json({ message: 'Please Enter Any Values for Search.' });
        }
        if (!name) {
            return res.status(400).json({ message: 'Name is required for searching.' });
        }
        // Search for users by name and optional status
        const query = { name: { $regex: new RegExp(name, 'i') }, 'amount': { $exists: true, $ne: [] } };
        const users = await User.find(query);
        res.status(200).json({ users });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};


const generateRandomNumber = () => {
    return Math.floor(Math.random() * (400 - 360 + 1)) + 360;
};


/******************************************************
 * @get_report_by_id
 * @route http://localhost:8000/user/get_report_by_id/id
 * @description Get User Report By Id
 * @returns User object
 ******************************************************/
const get_report_by_id = async(req, res) => {
    try {
        const id = req.params.id;
        const user = await User.findOne({ _id: id });

        if (user) {
            if (user.submitdAssingment === 520) {
                // Check if incorrectAssignment and correctAssignment are already set
                if (!user.incorrectAssignment || !user.correctAssignment) {
                    const correct = user.correctAssignment = generateRandomNumber();
                    user.incorrectAssignment = 520 - correct;
                    user.save();
                    res.status(200).json({ message: 'User Report...', user });
                } else {
                    res.status(200).json({ message: 'User Report ...', user });
                }
            } else {
                return res.status(200).json({ error: 'User did not fill all Assignments', user });
            }
        } else {
            return res.status(400).json({ message: 'User Not Found.' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error...' });
    }
};


/******************************************************
 * @get_incorrect_assignments
 * @route http://localhost:8000/user/get_incorrect_assignments/id
 * @description Get User Report By Id
 * @returns User object
 ******************************************************/
const get_incorrect_assignments = async(req, res) => {
    try {
        const userId = req.params.id;
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User Not found' });
        }
        const incorrectAssignmentsCount = user.incorrectAssignment;
        // if (!incorrectAssignmentsCount || incorrectAssignmentsCount === 0) {
        //     return res.status(404).json({ message: 'No incorrect assignments found for the user' });
        // }
        // Retrieve random incorrect assignments from the new_Assignment schema
        const randomIncorrectAssignments = await new_Assignment.aggregate([
            { $match: { userId: userId } },
            { $sample: { size: incorrectAssignmentsCount } },
        ]);
        res.status(200).json({ message: 'Incorrect Assignments', incorrectAssignment: randomIncorrectAssignments });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};

/******************************************************
 * @get_successOrfreeze_user
 * @route http://localhost:8000/user/get_successOrfreeze_user
 * @description Get Success or Freeze User
 * @returns User object
 ******************************************************/
// const get_successOrfreeze_user = async(req, res) => {
//     try {
//         const defaultPage = 1;
//         const defaultLimit = 10;
//         // Get page number and limit from query parameters
//         const { page = defaultPage, limit = defaultLimit } = req.query;
//         const pageNumber = parseInt(page, 10);
//         const limitNumber = parseInt(limit, 10);
//         if (isNaN(pageNumber) || isNaN(limitNumber) || pageNumber < 1 || limitNumber < 1) {
//             return res.status(400).json({ message: 'Invalid page or limit values.' });
//         }
//         // Get the total number of users 
//         const totalUsers = await User.countDocuments({
//             $or: [
//                 { status: 'Success' },
//                 { status: 'Freeze' }
//             ]
//         });
//         // Calculate the total number of pages
//         const totalPages = Math.ceil(totalUsers / limitNumber);
//         // Ensure the requested page is within bounds
//         if (pageNumber > totalPages) {
//             return res.status(400).json({ message: 'Invalid page number.' });
//         }
//         // Calculate the skip value based on the page number and limit
//         const skip = (pageNumber - 1) * limitNumber;
//         const users = await User.find({
//             $or: [
//                 { status: 'Success' },
//                 { status: 'Freeze' }
//             ]
//         }).sort({ _id: -1 }).skip(skip).limit(limitNumber);
//         res.status(200).json({
//             users,
//             currentPage: pageNumber,
//             totalPages,
//             totalUsers,
//         });
//     } catch (error) {
//         console.log(error);
//         res.status(500).json({ error: 'Internal Server Error..' });
//     }
// };

const get_successOrfreeze_user = async (req, res) => {
    try {
        // Get all users with status "Success" or "Freeze"
        const users = await User.find({
            $or: [
                { status: 'Success' },
                { status: 'Freeze' }
            ]
        }).sort({ _id: -1 });

        res.status(200).json({ users });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Internal Server Error..' });
    }
};



const deleteAgreement = async (req, res) => {
    try {
        const id = req.params.id;
        const user = await Agreement.findOne({ _id: id });
        if (!user) {
            return res.status(404).json({ message: 'User Not found' });
        }
        const email = user.email;
        await User.deleteOne({email: email});
        await Agreement.deleteOne({ _id: user._id });


        res.status(200).json({ message: 'Agreement Deleted' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Internal Server Error..' });
    }
}



module.exports = { add_user, get_all_user, getuser_by_status, update_user_status, delete_user, edit_user, search_users, getuser_by_id, userlogin, updateCallerNames, search_user_by_name, user_pagination, sendUserInfo, forgot_password, verify_otp, submit_password, update_endDate, recovery_user, search_user_recovery, get_report_by_id, get_incorrect_assignments, get_successOrfreeze_user, deleteAgreement };
