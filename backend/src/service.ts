import jwt from 'jsonwebtoken'
import crypto from 'crypto'
import { Pool } from 'pg'

const INVALID_PARAMETER = 422
const MISSING_AUTHORIZATION = 403
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
            res.status(MISSING_AUTHORIZATION)
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
        const query = "SELECT * FROM users WHERE auth_user_id = $1;"
        const value = [ u_id ]
        const qRes = await pool.query(query, value)
        // check if there is no such user
        if (qRes.rows.length === 0) {
            res.status(INVALID_PARAMETER)
            throw new Error("No such a user")
        }
        res.json(qRes.rows[0])

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
        console.log(req.body);
        
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


/**********************
 *  Channel functions *
 **********************/