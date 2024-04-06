import crypto from "crypto"
import jwt from "jsonwebtoken"
import { Pool } from "pg"

export const INVALID_PARAMETER = 422
export const ACCESS_ERROR = 403
export const INVALID_TOKEN = 401


export const pool = new Pool({
    user: 'jordan',
    host: 'localhost',
    database: 'project_express',
    password: process.env.SQL_PASSWORD,
    port: parseInt(process.env.SQL_PORT)
})

/*******************
 * Helper function *
********************/

type UserType = {
    email: string,
    password: string,
    sessionId?: number[]
}

// Generate a new token 
export const generateAccessToken = (user: UserType) => {
    return jwt.sign(user, process.env.SECRET_KEY, { expiresIn: '24h' })
}

// Hashing password
export const getHashOf = (str: string) => {
    return crypto.createHash('SHA256').update(str).digest('hex')
}

// Middleware function: Verifying authority
export const authenticateToken = (req: any, res: any, next: any) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) {
        res.status(INVALID_TOKEN)
        return res.send("Permission Denied")
    }

    jwt.verify(token,process.env.SECRET_KEY, (err: any, user: object) => {
        if (err) {
            res.status(ACCESS_ERROR)
            return res.send("Invalid Token")
        }
        console.log("// AuthenticateToken? user: ", user);
        
        res.locals.user = user
        next()
    })
}

export const validEmail = (email: string) => {
    const result = email.match('^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$')
    if (result === null) {
        throw new Error ("Error: Invalid Email")
    }
    return email
}

/*
    InputError:
        length of password is less than 6 characters
*/
export const validPassword = (pw: string) => {
    if (pw.length < 6) {
        throw new Error("Error: Invalid Password")
    }
    return pw
}

/*
    InputError:
        length of name_first is not between 1 and 50 characters inclusive
        length of name_last is not between 1 and 50 characters inclusive
*/
export const validName = (name: string) => {
    if (name.length < 1 || name.length > 50 ) {
        throw new Error("Error: Invalid Name")
    }
    return name
}

/*
    InputError:
        length of name is less than 1 or more than 20 characters
*/
export const validChannelName = (name: string) => {
    if (name.length < 1 || name.length > 20 ) {
        throw new Error("Error: Invalid Name")
    }
    return name
}

/*
    InputError:
        length of handle_str is not between 3 and 20 characters inclusive
        handle_str contains characters that are not alphanumeric
        the handle is already used by another user
*/
export const validUsername = (username: string) => {
    if (username.length < 3 || username.length > 20) {
        throw new Error("Invalid Username")
    }
    // todo: handle_str contains characters that are not alphanumeric

    return username
}

export const getPermissionId = async (auth_user_id: number) => {
    const query = "SELECT permission_id FROM users WHERE auth_user_id = $1;"
    const values = [ auth_user_id ]
    const qRes = await pool.query(query, values)
    return qRes.rows[0].permission_id
}

export const getCountGlobalOwner = async () => {
    const q1 = "SELECT * FROM users WHERE permission_id = 1;"
    const res1 = await pool.query(q1)
    return res1.rowCount
}
export const isPublicChannel = async (channel_id: number) => {
    const q1 = "SELECT is_public FROM channels WHERE channel_id = $1;"
    const v1 = [ channel_id ]
    const res1 = await pool.query(q1, v1)
    return res1.rows[0].is_public
}
/*
    Input Error:
        length of name_first is not between 1 and 50 characters inclusive
        length of name_last is not between 1 and 50 characters inclusive
*/

/*
    InputError when any of:
        u_id does not refer to a valid user
*/
export const checkUserId = async (res: any, auth_user_id: number) => {
    const query = "SELECT * FROM users WHERE auth_user_id = $1;"
    const values = [ auth_user_id ]
    const qRes = await pool.query(query, values)
    if (qRes.rowCount === 0) {
        res.status(INVALID_PARAMETER)
        throw new Error (`u_id does not refer to a valid user`)
    }
}

/*
    InputError when any of:
        channel_id does not refer to a valid channel
*/

export const checkChannelId = async (res:any, channel_id: number) => {
    const q_input_error_1 = "SELECT * FROM channels WHERE channel_id = $1;"
    const v_input_error_1 = [ channel_id ]
    const res_input_error_1 = await pool.query(q_input_error_1, v_input_error_1)        
    if (res_input_error_1.rowCount === 0){
        res.status(INVALID_PARAMETER)
        throw new Error(`channel_id does not refer to a valid channel`)
    }
}

/*
    InputError:
        u_id refers to a user who is already an owner of the channel
*/
export const testHasChannelUser = async (res: any, auth_user_id: number, channel_id: number) => {
    const q_input_error_2 = "SELECT * FROM channel_user WHERE channel_id = $1 and auth_user_id = $2;"
    const v_input_error_2 = [ channel_id, auth_user_id ]
    const res_input_error_2 = await pool.query(q_input_error_2, v_input_error_2)
    if (res_input_error_2.rowCount >= 1){
        res.status(INVALID_PARAMETER)
        throw new Error(`the authorised user is already a member of the channel`)
    }
}

export const testNotChannelUser = async (res: any, auth_user_id: number, channel_id: number) => {
    const q_input_error_2 = "SELECT * FROM channel_user WHERE channel_id = $1 and auth_user_id = $2;"
    const v_input_error_2 = [ channel_id, auth_user_id ]
    const res_input_error_2 = await pool.query(q_input_error_2, v_input_error_2)
    if (res_input_error_2.rowCount === 0){
        res.status(INVALID_PARAMETER)
        throw new Error(`the authorised user is already a member of the channel`)
    }
}

const padTwoDigits = (num: number) => {
    return num.toString().padStart(2, "0");
  }
  
export const dateInYyyyMmDdHhMmSs = (date: Date, dateDiveder: string = "-") => {
    // :::: Exmple Usage ::::
    // The function takes a Date object as a parameter and formats the date as YYYY-MM-DD hh:mm:ss.
    // 👇️ 2023-04-11 16:21:23 (yyyy-mm-dd hh:mm:ss)
    //console.log(dateInYyyyMmDdHhMmSs(new Date()));
  
    //  👇️️ 2025-05-04 05:24:07 (yyyy-mm-dd hh:mm:ss)
    // console.log(dateInYyyyMmDdHhMmSs(new Date('May 04, 2025 05:24:07')));
    // Date divider
    // 👇️ 01/04/2023 10:20:07 (MM/DD/YYYY hh:mm:ss)
    // console.log(dateInYyyyMmDdHhMmSs(new Date(), "/"));
    return (
      [
        date.getFullYear(),
        padTwoDigits(date.getMonth() + 1),
        padTwoDigits(date.getDate()),
      ].join(dateDiveder) +
      " " +
      [
        padTwoDigits(date.getHours()),
        padTwoDigits(date.getMinutes()),
        padTwoDigits(date.getSeconds()),
      ].join(":")
    );
  }
  

/*
    message_id does not refer to a valid message within a channel/DM that the authorised user has joined
*/

export const testChannelDmMsgId = async (res: any, message_id: number, auth_user_id: number) => {
    const query = "SELECT * FROM messages m JOIN channel_user cu ON m.channel_id = cu.channel_id WHERE cu.auth_user_id = $1 and m.message_id = $2;"
    const values = [ auth_user_id, message_id ]
    const qRes = await pool.query(query, values)
    if (qRes.rowCount === 0) {
        res.status(INVALID_PARAMETER)
        throw new Error(`message_id does not refer to a valid message within a channel/DM that the authorised user has joined`)
    }
}

/*
    the message was sent by the authorised user making this request
*/
export const testMessageFromUser = async (res: any, auth_user_id:number, message_id: number) => {
    const q1 = "SELECT auth_user_id, channel_id FROM messages WHERE message_id = $1;"
    const v1 = [ message_id ]
    const res1 = await pool.query(q1, v1)
    const sender_id = res1.rows[0].auth_user_id
    // the message was sent by the authorised user making this request
    if (sender_id !== auth_user_id) {
        res.status(INVALID_PARAMETER)
        throw new Error(`the message was not sent by the authorised user making this request`)
    }
}

/*
    the authorised user has owner permissions in the channel/DM
*/
export const testUserIsOwner = async (res:any, auth_user_id:number, message_id: number) => {
    const q1 = "SELECT auth_user_id, channel_id FROM messages WHERE message_id = $1;"
    const v1 = [ message_id ]
    const res1 = await pool.query(q1, v1)
    const channel_id = res1.rows[0].channel_id
    const q2 = "SELECT is_owner FROM channel_user WHERE auth_user_id = $1 and channel_id = $2;"
    const v2 = [ auth_user_id, channel_id ]
    const is_owner = (await pool.query(q2, v2)).rows[0].is_owner
    if (!is_owner) {
        res.status(INVALID_PARAMETER)
        throw new Error(`the authorised user has owner permissions in the channel/DM`)
    }
}
