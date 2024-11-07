import jwt from "jsonwebtoken";
const protect = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1]; // Get token from the "Authorization" header
    
    if (!token) {
        return res.status(401).json({ message: 'No token provided, authorization denied' });
    }

    try {
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Attach user data to the request
        next(); // Proceed to the next middleware or route handler
    } catch (error) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};
export default protect;
