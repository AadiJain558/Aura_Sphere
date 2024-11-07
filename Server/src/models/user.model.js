import mongoose from "mongoose"
import bcrypt from "bcryptjs"
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    studyGroups: [
        { type: mongoose.Schema.Types.ObjectId, ref: "StudyGroup" }
    ],
    virtualRooms: [
        { type: mongoose.Schema.Types.ObjectId, ref: "VirtualRoom" }
    ],
    password: {
        type: String,
    },
    friends: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    }],
    avatar: {
        type: String,
        default: "www.lobstertube.com"
    },
    aurapoints: {
        type: Number,
        default: 0
    },
    level: {
        type: Number,
        default: 1,
    },
    rewardHistory: [
        {
            reward: String,
            date: {
                type: Date,
                default: Date.now
            },
        },
    ],
    department: {
        type:mongoose.Schema.Types.ObjectId,
        ref:"Dept"
    },
    year: {
        type: Number,
        default: 2000
    },
    badges: {
        type: Array,
        default: []
    },
    dueassignments: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "Assignment"
    }],
    completedassignments: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "Assignment"
    }],
    attendance: {
        type: Array,
        default: []
    },
    rank: {
        type: Number,
        default: 10000
    },
    academicGoals: [
        {
            goal: String,
            targetDate: Date,
            completed: { type: Boolean, default: false }
        }
    ], // Store each goal with a target date and completion status
    courseSchedule: [
        {
            courseName: String,
            day: String,
            startTime: String,
            endTime: String
        }
    ], // Track each course schedule entry
    progress: {
        type: Map,
        of: Number,
        default: {}
    } 

})


// Course Schema




// Hash the password before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

userSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

// Add or update an academic goal
userSchema.methods.addOrUpdateGoal = async function(goalId, goalDetails) {
    const goalIndex = this.academicGoals.findIndex(g => g._id.toString() === goalId);
    if (goalIndex !== -1) {
        // Update existing goal
        this.academicGoals[goalIndex] = { ...this.academicGoals[goalIndex], ...goalDetails };
    } else {
        // Add new goal
        this.academicGoals.push(goalDetails);
    }
    await this.save();
    return this.academicGoals;
};

// Remove an academic goal
userSchema.methods.removeGoal = async function(goalId) {
    this.academicGoals = this.academicGoals.filter(g => g._id.toString() !== goalId);
    await this.save();
    return this.academicGoals;
};

// Add or update a course schedule
userSchema.methods.addOrUpdateCourse = async function(courseId, courseDetails) {
    const courseIndex = this.courseSchedule.findIndex(c => c._id.toString() === courseId);
    if (courseIndex !== -1) {
        // Update existing course
        this.courseSchedule[courseIndex] = { ...this.courseSchedule[courseIndex], ...courseDetails };
    } else {
        // Add new course
        this.courseSchedule.push(courseDetails);
    }
    await this.save();
    return this.courseSchedule;
};

// Remove a course from the schedule
userSchema.methods.removeCourse = async function(courseId) {
    this.courseSchedule = this.courseSchedule.filter(c => c._id.toString() !== courseId);
    await this.save();
    return this.courseSchedule;
};

// Update progress for a specific goal
userSchema.methods.updateProgress = async function(goalId, progressPercentage) {
    if (this.progress.has(goalId)) {
        this.progress.set(goalId, progressPercentage);
    } else {
        this.progress.set(goalId, progressPercentage);
    }
    await this.save();
    return this.progress;
};

// Fetch all goals with their progress
userSchema.methods.getGoalsWithProgress = async function() {
    return this.academicGoals.map(goal => ({
        ...goal.toObject(),
        progress: this.progress.get(goal._id.toString()) || 0
    }));
};

userSchema.methods.getTimetable = async function () {
    const courses = await Course.find({ _id: { $in: this.courses } }).populate('assignments');
    const timetable = [];

    courses.forEach(course => {
        course.schedule.forEach(timeSlot => {
            timetable.push({
                courseTitle: course.title,
                instructor: course.instructor,
                day: timeSlot.day,
                startTime: timeSlot.startTime,
                endTime: timeSlot.endTime,
                assignments: course.assignments
            });
        });
    });

    return timetable;
};
userSchema.methods.awardPoints = async function (points) {
    this.aurapoints += points;

    // Check for level up (e.g., every 100 points = new level)
    const levelThreshold = 100;
    const newLevel = Math.floor(this.aurapoints / levelThreshold) + 1;

    if (newLevel > this.level) {
        this.level = newLevel;
    }
    await this.save();
};

userSchema.methods.redeemReward = async function (reward) {
    // Add a record of redeemed reward
    this.rewardHistory.push({ reward });
    await this.save();
};



export const User = mongoose.model("User", userSchema)
