import jwt from 'jsonwebtoken'
import {Request,Response,NextFunction} from 'express'
import {generateAccessToken} from '../utils/generateAccessToken'

interface userPayload{
    _id:string,
    email:string,
    role:string
}

declare global{
    namespace Express{
        interface Request{
            user?:userPayload
        }
    }
}

export const jwtMiddleware=async(req:Request,res:Response,next:NextFunction):Promise<void>=>{
    try{
        const { access_token, refresh_token } = req.cookies;
        console.log('access_token',access_token)
        console.log('refresh_token',refresh_token)

        if(!access_token&&!refresh_token){
            return next()
        }

        let user:userPayload|undefined
        
        if(access_token){
            try{
                user=await jwt.verify(access_token,process.env.ACCESS_TOKEN_SECRET!) as userPayload
            }catch(error:any){
                if(error.name!=='TokenExpiredError'){
                    console.error('Access token verification error:',error);
                    return next()
                    
                }
                console.log('Access token expired')
            }
        }
        if(!user&&refresh_token){
            try{
                user = user = await jwt.verify(
                  refresh_token,
                  process.env.REFRESH_TOKEN_SECRET!
                ) as userPayload;


                console.log('refresh token',user)
                if(user){
                    const newAccessToken=generateAccessToken(user)
                    res.cookie('access_token',newAccessToken,{httpOnly:true})

                    console.log('New access token generated')
                }
            }catch(error:any){
                console.error('refresh token verification error:',error);
            return next()
                
            }
        }
        req.user=user
        next()
        
    }catch(error:any){
        console.error('Error in JWT middleware:',error);
        next(error) // cal next with error to handle it properly in the middleware chain 
        
        
    }
}