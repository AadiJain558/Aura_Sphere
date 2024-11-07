import express from 'express';
import {User} from '../models/user.model.js'; // Adjust path as necessary
import { Router } from 'express';
import jwt from 'jsonwebtoken';
import { getLeaderboard } from '../controller/userController.js';
const router = Router();
router.get('/leaderboard', getLeaderboard);
export default router;