/**
 * Authentication Middleware
 */

import { Request, Response, NextFunction } from 'express';
import { getAuthService } from '../../src/services/authService';

export interface AuthenticatedRequest extends Request {
  user?: {
    userId: string;
    email: string;
    nickname?: string;
  };
}

export async function authMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Missing or invalid authorization header',
      });
      return;
    }

    const token = authHeader.substring(7);
    const authService = getAuthService();
    const decodedToken = await authService.verifyToken(token);

    req.user = {
      userId: decodedToken.sub,
      email: decodedToken.email,
      nickname: decodedToken.preferred_username,
    };

    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid or expired token',
    });
  }
}

export async function optionalAuthMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const authService = getAuthService();
      const decodedToken = await authService.verifyToken(token);

      req.user = {
        userId: decodedToken.sub,
        email: decodedToken.email,
        nickname: decodedToken.preferred_username,
      };
    }

    next();
  } catch (error) {
    next();
  }
}
