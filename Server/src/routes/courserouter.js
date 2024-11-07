import express from "express";
import { Course} from "../models/Course.js"; // Assuming course and assignment are in Course.js file
import { Assignment } from "../models/assignment.model.js";
import protect  from "../middleware/auth.js";
import { User } from "../models/user.model.js";

const router = express.Router();

// Add a course
router.post("/courses", protect, async (req, res) => {
    const { title, instructor, schedule } = req.body;
    try {
        const course = await Course.create({ title, instructor, schedule });
        res.status(201).json(course);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Add an assignment to a course
router.post("/assignments", protect, async (req, res) => {
    const { title, dueDate, courseId, description } = req.body;
    try {
        const assignment = await Assignment.create({ title, dueDate, course: courseId, description });
        const course = await Course.findById(courseId);
        course.assignments.push(assignment._id);
        await course.save();
        res.status(201).json(assignment);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Get user's timetable
router.get("/timetable", protect, async (req, res) => {
    try {
        const user = await User.findById(req.userId).populate({
            path: 'courses',
            populate: { path: 'assignments' }
        });
        const timetable = await user.getTimetable();
        res.status(200).json(timetable);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

export default router;
