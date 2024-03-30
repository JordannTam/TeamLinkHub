import jwt from 'jsonwebtoken'
import crypto from 'crypto'
import { Pool } from 'pg'

const INVALID_PARAMETER = 422
const ACCESS_ERROR = 403
const INVALID_TOKEN = 401


const pool = new Pool({
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

const validEmail = (email: string) => {
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
const validPassword = (pw: string) => {
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
const validName = (name: string) => {
    if (name.length < 1 || name.length > 50 ) {
        throw new Error("Error: Invalid Name")
    }
    return name
}

/*
    InputError:
        length of name is less than 1 or more than 20 characters
*/
const validChannelName = (name: string) => {
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
const validUsername = (username: string) => {
    if (username.length < 3 || username.length > 20) {
        throw new Error("Invalid Username")
    }
    // todo: handle_str contains characters that are not alphanumeric

    return username
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
const checkUserId = async (res: any, auth_user_id: number) => {
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

const checkChannelId = async (res:any, channel_id: number) => {
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
const checkNotChannelUser = async (res: any, auth_user_id: number, channel_id: number) => {
    const q_input_error_2 = "SELECT * FROM channel_user WHERE channel_id = $1 and auth_user_id = $2;"
    const v_input_error_2 = [ channel_id, auth_user_id ]
    const res_input_error_2 = await pool.query(q_input_error_2, v_input_error_2)
    if (res_input_error_2.rowCount >= 1){
        res.status(INVALID_PARAMETER)
        throw new Error(`the authorised user is already a member of the channel`)
    }
}

const checkHasChannelUser = async (res: any, auth_user_id: number, channel_id: number) => {
    const q_input_error_2 = "SELECT * FROM channel_user WHERE channel_id = $1 and auth_user_id = $2;"
    const v_input_error_2 = [ channel_id, auth_user_id ]
    const res_input_error_2 = await pool.query(q_input_error_2, v_input_error_2)
    if (res_input_error_2.rowCount === 0){
        res.status(INVALID_PARAMETER)
        throw new Error(`the authorised user is already a member of the channel`)
    }
}


/*****************
 * Auth Function *
 *****************/

/* 
    method : POST
    Authorized: True
    Parameters: { email, password }
    Return Type: { token, auth_user_id }
    Associate path: /auth/login

    Error:
    InputError when any of:
        email entered does not belong to a user
        password is not correct
*/
export const auth_login = async (req: any, res: any) => {
    const email = req.body.email
    const password = getHashOf(req.body.password)
    const query = "SELECT * FROM users WHERE email = ($1) AND password = ($2);"
    const values = [ email, password ]
    
    try {
        const qRes = await pool.query(query, values)
        if (qRes.rows.length === 0) {
            res.status(INVALID_PARAMETER)
            return res.send(`Error: Incorrect Email or Password`)
        }
        const user = qRes.rows[0]
        const token = generateAccessToken(user)

        return res.json({ token: token, auth_user_id: user.auth_user_id})

    } catch (err) {
        res.status(INVALID_TOKEN)
        return res.send(`${err}`);
    }
}

/*
    method : POST
    Authorized: True
    Parameters: { email, password, name_first, name_last }
    Return Type: { token, auth_user_id }
    Associate path: /auth/register

    Error:
    InputError when any of:
        email entered is not a valid email (more in section 6.4)
        email address is already being used by another user
        length of password is less than 6 characters
        length of name_first is not between 1 and 50 characters inclusive
        length of name_last is not between 1 and 50 characters inclusive
*/

export const auth_register = async (req: any, res: any) => {
    let email = ""
    let password = ""
    try {
        email = validEmail(req.body.email)
        password = getHashOf(validPassword(req.body.password))
    } catch (err) {
        res.status(INVALID_PARAMETER)
        return res.send(`Error: ${err}`)
    }
    try {
        const name_first = req.body.name_first
        const name_last = req.body.name_last
        const createat = Date.now().toString()
        // Searching if a same email has been used
        const queryEmail = "SELECT * FROM users where email = $1;"
        const valueEmail = [ email ]
        const qResEmail = await pool.query(queryEmail, valueEmail)
        if (qResEmail.rows.length !== 0) {
            res.status(INVALID_PARAMETER)
            return res.send("Email has been used")
        }
        const query = "INSERT INTO users (email, password, name_first, name_last, createat) values ($1, $2, $3, $4, $5) RETURNING auth_user_id;"
        const values = [ email, password, name_first, name_last, createat ]
        const qRes = await pool.query(query, values)
        const auth_user_id = qRes.rows[0].auth_user_id
        const user = { 
            auth_user_id: auth_user_id, 
            email: email,
            password: password,
            name_first: name_first,
            name_last: name_last 
        }
        const token = generateAccessToken(user)
        res.json({ token: token, auth_user_id: auth_user_id})
        return ;
    } catch(err) {
        console.error(`// Error: function *auth_register* ${err}`);
    }
}



/**********************
 *  Channel functions *
 **********************/

/*
    method: POST
    Parameters: { token, name, is_public }
    Return Type: { channel_id }
    Path: /channels/create

    Error:
    InputError when:
        length of name is less than 1 or more than 20 characters
*/

export const channelCreate = async (req: any, res: any) => {
    try {
        const user = res.locals.user
        const name = validChannelName(req.body.name)
        if (req.body.is_public === undefined || typeof(req.body.is_public) !== 'boolean') {
            throw new Error(`Invalid Input `)
        }
        const is_public =  req.body.is_public
        const query = "INSERT INTO channels (name, is_public) values ($1, $2) RETURNING channel_id;"
        const values = [ name, is_public ]
        const qRes = await pool.query(query, values)
        const channel_id = qRes.rows[0].channel_id
        const query_add_user = "INSERT INTO channel_user (channel_id, auth_user_id, is_owner) VALUES ($1, $2, $3);"
        const values_add_user = [ channel_id, user.auth_user_id, true ]
        await pool.query(query_add_user, values_add_user)

        return res.json({ channel_id })

    } catch(err) {
        res.status(INVALID_PARAMETER)
        return res.send(`Error: ${err}`)
    }
}

/*
    Parameters: { token }
    Return Type: { channels }
    path: /channels/list/
*/

export const channelsList = async (req: any, res: any) => {
    try {
        const user = res.locals.user
        const query = `SELECT c.channel_id, c.name, c.is_public, json_agg( json_build_object( 'user_id', cu.auth_user_id,  'is_owner', cu.is_owner,  'username', u.username,  'name_first', name_first,  'name_last', name_last,  'email', email,  'permission_id', permission_id,  'img', img  ) ) AS members  FROM channels c JOIN channel_user cu ON c.channel_id = cu.channel_id JOIN users u ON cu.auth_user_id = u.auth_user_id WHERE cu.channel_id IN (SELECT DISTINCT channel_id FROM channel_user WHERE auth_user_id = $1) GROUP BY c.channel_id;`
        const values = [ user.auth_user_id ]
        const qRes = await pool.query(query, values)
        res.json(qRes.rows)
    } catch(err) {
        res.status(INVALID_TOKEN)
        return res.send(`Error: ${err}`)
    }
}

/*
    Parameters: { token }
    Return Type: { channels }
    path: /channels/listall/

*/

export const channelsListAll = async (req: any, res: any) => {
    try {
        const query = "SELECT * FROM channels;"
        const qRes = await pool.query(query)
        res.json(qRes.rows)
    } catch(err) {
        res.status(INVALID_TOKEN)
        return res.send(`Error: ${err}`)
    }
}

/*
    Parameters: { token, channel_id }
    Return Type: { name, is_public, owner_members, all_members }    
    path: /channel/details/

    Error:
    InputError when:
        channel_id does not refer to a valid channel
    AccessError when:
        the authorised user is not a member of the channel
*/

export const channelDetails = async (req: any, res: any) => {
    try {
        const channel_id = req.query.channel_id
        const auth_user_id = res.locals.user.auth_user_id
        await checkNotChannelUser(res, channel_id, auth_user_id)
        const query = "SELECT c.name, c.is_public, json_agg(json_build_object('user_id', cu.auth_user_id, 'is_owner', cu.is_owner, 'username', u.username, 'name_first', name_first, 'name_last', name_last, 'email', email, 'permission_id', permission_id, 'img', img )) AS members FROM channels c JOIN channel_user cu ON c.channel_id = cu.channel_id JOIN users u ON cu.auth_user_id = u.auth_user_id WHERE c.channel_id = $1 GROUP BY c.channel_id"
        const values = [ channel_id ]
        const qRes = await pool.query(query, values)
        res.json(qRes.rows[0])
    } catch(err) { 
        res.status(INVALID_PARAMETER)
        return res.send(`Error: ${err}`)
    }
}

/*
    Parameters: { token, channel_id }
    Return Type: {}   
    path: /channel/join

    Error:
    InputError when any of:
        channel_id does not refer to a valid channel
        the authorised user is already a member of the channel
    AccessError when:
        channel_id refers to a channel that is private and the authorised user is not already a channel member and is not a global owner
*/

export const channelJoin = async (req: any, res: any) => {
    try {
        const channel_id = req.body.channel_id
        await checkChannelId(res, channel_id)
        const auth_user_id = res.locals.user.auth_user_id
        await checkNotChannelUser(res, auth_user_id, channel_id)
        const q_access_error_1_1 = "SELECT is_public FROM channels WHERE channel_id = $1;"
        const v_access_error_1_1 = [ channel_id ]
        const res_access_error_1_1 = await pool.query(q_access_error_1_1, v_access_error_1_1)
        if (!res_access_error_1_1.rows[0].is_public) {
            res.status(ACCESS_ERROR)
            throw new Error(`channel_id refers to a channel that is private`)
        }
        const query = "INSERT INTO channel_user (channel_id, auth_user_id, is_owner) VALUES ($1, $2, $3);"
        const values = [ channel_id, auth_user_id, false]
        await pool.query(query, values)
        res.json({})
    } catch(err) {
        return res.send(`Error: ${err}`)
    }
}

/*
    Method: POST
    Parameters: { token, channel_id, u_id }
    Return Type: {}
    path: /channel/invite

    Error:
    InputError when any of:
        channel_id does not refer to a valid channel
        u_id does not refer to a valid user
        u_id refers to a user who is already a member of the channel
    AccessError when:
        channel_id is valid and the authorised user is not a member of the channel
*/

export const channelInvite = async (req: any, res: any) => {
    try { 
        const user = res.locals.user
        const channel_id = req.body.channel_id
        const target_u_id = req.body.u_id
        // channel_id does not refer to a valid channel
        await checkChannelId(res, channel_id)
        // u_id does not refer to a valid user
        await checkUserId(res, target_u_id)

        // u_id refers to a user who is already a member of the channel
        await checkNotChannelUser(res, channel_id, target_u_id)
        // channel_id is valid and the authorised user is not a member of the channel
        const q_access_error_3 = "SELECT * FROM channel_user WHERE channel_id = $1 and auth_user_id = $2;"
        const v_access_error_3 = [ channel_id, user.auth_user_id ]
        const res_access_error_3 = await pool.query(q_access_error_3, v_access_error_3)
        if (res_access_error_3.rowCount === 0) {
            res.status(ACCESS_ERROR)
            throw new Error (`channel_id is valid and the authorised user is not a member of the channel`)
        }

        const query = "INSERT INTO channel_user (channel_id, auth_user_id, is_owner) VALUES ($1, $2, $3);"
        const values = [ channel_id, target_u_id, false ]
        pool.query(query, values)
        res.json({})

    } catch(err) {
        return res.send(`Error: ${err}`)
    }
}

/*
    Method: POST
    Parameters: { token, channel_id }
    Return Type: {}
    Path: /channel/leave

    InputError when any of:
        channel_id does not refer to a valid channel
        the authorised user is the starter of an active standup in the channel
    AccessError when:
        channel_id is valid and the authorised user is not a member of the channel
*/
export const channelLeave = async (req: any, res: any) => {
    try {
        const channel_id = req.body.channel_id
        const auth_user_id = res.locals.user.auth_user_id
        console.log(channel_id, auth_user_id);
        
        await checkChannelId(res, channel_id)
        const q = await pool.query("SELECT * FROM channel_user WHERE auth_user_id = $1 and channel_id = $2;", [ auth_user_id, channel_id ])
        console.log(q.rows[0]);
        
        const query = "DELETE FROM channel_user WHERE auth_user_id = $1 and channel_id = $2;"
        const values = [ auth_user_id, channel_id ]
        await pool.query(query, values)
        return res.json({})
    } catch(err) {
        return res.send(`Error: ${err}`)
    }
}


/*
    Method: post
    Parameters: { token, channel_id, u_id }
    Return Type: {}
    Path: /channel/addowner

    Error:
    InputError when any of:
        channel_id does not refer to a valid channel
        u_id does not refer to a valid user
        u_id refers to a user who is not a member of the channel
        u_id refers to a user who is already an owner of the channel
    AccessError when:
        channel_id is valid and the authorised user does not have owner permissions in the channel
*/

export const channelAddowner = async (req: any, res: any) => {
    try {
        const auth_user_id = res.locals.user.auth_user_id
        const channel_id = req.body.channel_id
        const target_u_id = req.body.u_id
        await checkChannelId(res, channel_id)
        await checkUserId(res, target_u_id)
        await checkHasChannelUser(res, target_u_id, channel_id)
        const q_input_error_owner = "SELECT * FROM channel_user WHERE channel_id = $1 and auth_user_id = $2;"
        const v_input_error_owner = [ channel_id, target_u_id]
        const res_input_error_owner = await pool.query(q_input_error_owner, v_input_error_owner)
        if (res_input_error_owner.rows[0].is_owner) {
            res.status(INVALID_PARAMETER)
            throw new Error(`u_id refers to a user who is already an owner of the channel`)
        }
        const q_access_error_owner = "SELECT * FROM channel_user WHERE channel_id = $1 and auth_user_id = $2;"
        const v_access_error_owner = [ channel_id, auth_user_id]
        const res_access_error_owner = await pool.query(q_access_error_owner, v_access_error_owner)
        if (!res_access_error_owner.rows[0].is_owner) {
            res.status(INVALID_PARAMETER)
            throw new Error(`channel_id is valid and the authorised user does not have owner permissions in the channel`)
        }
        const query = "UPDATE channel_user SET is_owner = true WHERE channel_id = $1 and auth_user_id = $2;"
        const values = [ channel_id, target_u_id ]
        await pool.query(query, values)
        res.json({})

    } catch(err) {
        return res.send(`Error: ${err}`)
    }
}

/*
    Method: post
    Parameters: { token, channel_id, u_id }
    Return Type: {}
    Path: /channel/addowner

    Error:
    InputError when any of:
        channel_id does not refer to a valid channel
        u_id does not refer to a valid user
        u_id refers to a user who is not an owner of the channel
        u_id refers to a user who is currently the only owner of the channel
    AccessError when:
        channel_id is valid and the authorised user does not have owner permissions in the channel
*/

export const channelRemoveowner = async (req: any, res: any) => {
    try {
        const auth_user_id = res.locals.user.auth_user_id
        const channel_id = req.body.channel_id
        const target_u_id = req.body.u_id
        await checkChannelId(res, channel_id)
        await checkUserId(res, target_u_id)
        await checkHasChannelUser(res, target_u_id, channel_id)
        const q_input_error_owner = "SELECT * FROM channel_user WHERE channel_id = $1;"
        const v_input_error_owner = [ channel_id ]
        const res_input_error_owner = await pool.query(q_input_error_owner, v_input_error_owner)
        let hasOtherOwner = false
        for (const user of res_input_error_owner.rows) {
            if (user.auth_user_id !== target_u_id && user.is_owner){
                hasOtherOwner = true
            }
        }
        if (!hasOtherOwner) {
            res.status(INVALID_PARAMETER)
            throw new Error(`u_id refers to a user who is currently the only owner of the channel`)
        }
        const q_access_error_owner = "SELECT * FROM channel_user WHERE channel_id = $1 and auth_user_id = $2;"
        const v_access_error_owner = [ channel_id, auth_user_id]
        const res_access_error_owner = await pool.query(q_access_error_owner, v_access_error_owner)
        if (!res_access_error_owner.rows[0].is_owner) {
            res.status(INVALID_PARAMETER)
            throw new Error(`channel_id is valid and the authorised user does not have owner permissions in the channel`)
        }
        const query = "UPDATE channel_user SET is_owner = false WHERE channel_id = $1 and auth_user_id = $2;"
        const values = [ channel_id, target_u_id ]
        await pool.query(query, values)
        res.json({})

    } catch(err) {
        return res.send(`Error: ${err}`)
    }
}


/********************
 * Message Function *
 ********************/





/*****************
 * User Function *
 *****************/
/*
    method : GET
    Authorized: True
    Parameters: {}
    Return Type: { users }
    Associate path: /users/all

    Error:
        None
*/

export const usersAll = async (req: any, res: any) => {
    const query = "SELECT * FROM users;"
    try {
        const qRes = await pool.query(query)
        const users = qRes.rows
        res.json(users)
    } catch (err) {
        console.error(`// Error: function *usersAll* ${err}`);
    }
}

/*
    method : GET
    Authorized: True
    Parameters: { token, u_id }
    Return Type: { user }
    Associate path: /user/profile

    Error:
    InputError when:
        u_id does not refer to a valid user
*/

export const userProfile = async (req: any, res: any) => {
    try {
        const u_id = parseInt(req.query.u_id)
        // check if the u_id is not valid
        if (u_id <= 0) {
            res.status(INVALID_PARAMETER)
            throw new Error("Invalid u_id")
        }
        await checkUserId(res, u_id)

    } catch (err) {
        return res.send(`Error: ${err} `)
    }
}

/*
    method : PUT
    Authorized: True
    Parameters: { token, name_first, name_last }
    Return Type: {}
    Associate path: /user/profile/setname

    Error:
    InputError when:
        length of name_first is not between 1 and 50 characters inclusive
        length of name_last is not between 1 and 50 characters inclusive
*/


export const userSetName = async (req: any, res: any) => {
    try {        
        const name_first = validName(req.body.name_first)
        const name_last = validName(req.body.name_last)
        const u_id = res.locals.user.auth_user_id

        const query = "UPDATE users SET name_first = $1, name_last = $2 WHERE auth_user_id = $3;"
        const values = [ name_first, name_last, u_id ]
        const qRes = await pool.query(query, values)
        return res.json({})

    } catch (err) {
        res.status(INVALID_PARAMETER)
        return res.send(`Error: ${err}`)
    }
}
/*
    method : PUT
    Authorized: True
    Parameters: { token, email }
    Return Type: {}
    Associate path: /user/profile/setemail

    Error:
    InputError when:
        length of name_first is not between 1 and 50 characters inclusive
        length of name_last is not between 1 and 50 characters inclusive
*/

export const userSetEmail = async (req: any, res: any) => {
    try {
        const newEmail = validEmail(req.body.email)
        const u_id = res.locals.user.auth_user_id
        // Checking if the email has been used
        const queryCheck = "SELECT * FROM users where email = $1;"
        const valueCheck = [ newEmail ]
        
        const qResCheck = await pool.query(queryCheck, valueCheck)
        if (qResCheck.rows.length !== 0){
            throw new Error('Email has been used')
        }
        const query = "UPDATE users SET email = $1 WHERE auth_user_id = $2;"
        const values = [ newEmail, u_id ]
        const qRes = await pool.query(query, values)

        return res.json({})

    } catch (err) {
        res.status(INVALID_PARAMETER)
        return res.send(`Error: ${err}`)
    }
}

/*
    method : PUT
    Authorized: True
    Parameters: { token, handle_str }
    Return Type: {}
    Associate path: /user/profile/sethandle

    Error:
    InputError when any of:
        length of handle_str is not between 3 and 20 characters inclusive
        handle_str contains characters that are not alphanumeric
        the handle is already used by another user
*/

export const userSetHandle = async (req: any, res: any) => {
    try {
        const username = validUsername(req.body.handle_str)
        const u_id = res.locals.user.auth_user_id
        // Checking if the email has been used
        const queryCheck = "SELECT * FROM users where username = $1;"
        const valueCheck = [ username ]
        
        const qResCheck = await pool.query(queryCheck, valueCheck)
        if (qResCheck.rows.length !== 0){
            throw new Error('Username has been used')
        }
        const query = "UPDATE users SET username = $1 WHERE auth_user_id = $2;"
        const values = [ username, u_id ]
        await pool.query(query, values)

        return res.json({})

    } catch (err) {
        res.status(INVALID_PARAMETER)
        return res.send(`Error: ${err}`)
    }
}

