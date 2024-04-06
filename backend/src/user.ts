import { 
    INVALID_PARAMETER,
    checkUserId,
    pool,
    validEmail,
    validName,
    validUsername 
} from './util'

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
        return res.send(`${err} `)
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
        return res.send(`${err} `)
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
        return res.send(`${err}`)
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
        return res.send(`${err}`)
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
        return res.send(`${err}`)
    }
}
