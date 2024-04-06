/*****************
 * Auth Function *
 *****************/

import { INVALID_PARAMETER, INVALID_TOKEN, generateAccessToken, getHashOf, pool, validEmail, validPassword } from "./util"

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
            return res.send(`Incorrect Email or Password`)
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
        return res.send(`${err}`)
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
        return res.send(`Error ${err}`);
    }
}
