import { Request, Response, NextFunction } from "express";

interface User {
  role: string;
  [key: string]: any; // Other user properties
}

// RoleMiddleware function that accepts required roles as parameters
export const roleMiddleware = (requiredRoles: string[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = req.user as User;

    if (!user) {
      return res
        .status(401)
        .json({ message: "Unauthorized: No user found in request" });
    }

    if (!requiredRoles.includes(user.role)) {
      return res
        .status(403)
        .json({
          message: "Forbidden: You do not have the required permissions",
        });
    }

    next();
  };
};
