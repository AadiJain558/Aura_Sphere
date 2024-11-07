import express from 'express'
import dotenv from 'dotenv';
import connectDB from './db/connect.js';
import auth from './routes/auth.js';
import goalrouter from './routes/goals.js';
import { mongo } from 'mongoose';
import session from 'express-session';
import passport from 'passport';
import './passport.js';
import {User} from './models/user.model.js';
import userrouter from './routes/userroute.js';
import cors from 'cors';
import courseRouter from "./routes/courserouter.js";
import gamificationRouter from "./routes/gamificiation.js";
import lead from './routes/leaderboardroute.js';
import challengeRoutes from "./routes/challengeRoutes.js";
import addpt from './routes/addpt.js';
import userRoutes from './routes/userroute.js';

import { errorHandler } from './middleware/errorHandler.js';
dotenv.config({path: './.env'});
const app = express()
connectDB()
.then(()=>{
  app.listen(process.env.PORT,()=>{
      console.log(`Server is running on port ${process.env.PORT}`);
  });
})
.catch((error)=>{
  console.log(error);
  process.exit(1);
});

app.use(cors({ origin: 'http://localhost:5173' }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));


app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/userinfo',userrouter);
app.use('/auth',auth);
app.use('/api/user', addpt);
app.use('/userr',lead);
app.use(errorHandler);
app.use('/user',goalrouter);

app.use('/courses', courseRouter);
app.use("/api/gamification", challengeRoutes);
app.use("/gamification", gamificationRouter);
app.use("/api/gamification", challengeRoutes);



