import { 
    ACCESS_ERROR,
    INVALID_PARAMETER,
    checkUserId,
    getCountGlobalOwner,
    getPermissionId,
    pool 
} from './util'

/******************
 * Admin Function *
 ******************/

/*
    Parameters: { token, u_id }
    Return Type:{}
    InputError when any of: 
        u_id does not refer to a valid user
        u_id refers to a user who is the only global owner
    AccessError when:
        the authorised user is not a global owner
*/

export const adminUserRemove = async (req:any, res:any) => {
    try{
        const auth_user_id = res.locals.user.auth_user_id
        const target_u_id = req.query.u_id
        //  u_id does not refer to a valid user
        await checkUserId(res, target_u_id)

        // the authorised user is not a global owner
        const permission_id = await getPermissionId(auth_user_id)
        if (permission_id === 2) {
            throw new Error(`the authorised user is not a global owner`)
        }

        // u_id refers to a user who is the only global owner
        const targetPermission = await getPermissionId(target_u_id)
        const countGlobalOwner = await getCountGlobalOwner()
        if (targetPermission === 1 && countGlobalOwner === 1) {
            throw new Error(`u_id refers to a user who is the only global owner`)
        }
        
        const q1 = "UPDATE messages SET auth_user_id = -1 WHERE auth_user_id = $1"
        const v1 = [ target_u_id ]
        await pool.query(q1, v1)
        // Delete user
        const query = "DELETE FROM users WHERE auth_user_id = $1;"
        const values = [ target_u_id ]
        await pool.query(query, values)

        // Once users are removed, the contents of the messages they sent will be replaced by 'Removed user'
        res.json({})

    } catch (err) {
        return res.send(`${err}`)
    }

}

/*
    method: POST
    Parameters: { token, u_id, permission_id }
    Return Type: {}
    path: admin/userpermission/change/

    InputError when any of:
        u_id does not refer to a valid user
        u_id refers to a user who is the only global owner and they are being demoted to a user
        permission_id is invalid
        the user already has the permissions level of permission_id
    AccessError when:
        the authorised user is not a global owner
*/
export const adminUserpermissionChange = async (req:any, res:any) => {
    try {
        const u_id = req.body.u_id
        const permission_id = parseInt(req.body.u_id)
        const auth_permission_id = res.locals.user.permission_id
        //u_id does not refer to a valid user
        await checkUserId(res, u_id)
        //u_id refers to a user who is the only global owner and they are being demoted to a user
        if (await getPermissionId(u_id) === 1 && await getCountGlobalOwner() === 1){
            res.status(INVALID_PARAMETER)
            throw new Error(`u_id refers to a user who is the only global owner and they are being demoted to a user`)
        }
        //permission_id is invalid
        if (!(permission_id === 1 || permission_id === 2) ){
            res.status(INVALID_PARAMETER)
            throw new Error(`permission_id is invalid`)
        }
        //the user already has the permissions level of permission_id
        if (await getPermissionId(u_id) === permission_id) {
            res.status(INVALID_PARAMETER)
            throw new Error(`the user already has the permissions level of permission_id`)
        }
        //the authorised user is not a global owner
        if (auth_permission_id !== 1){
            res.status(ACCESS_ERROR)
            throw new Error(`the authorised user is not a global owner`)
        }
        const query = "UPDATE users SET permission_id = $1 WHERE auth_user_id = $2;"
        const values = [ permission_id, u_id ]
        await pool.query(query, values)
        res.json({})

    } catch (err) {
        return res.send(`${err}`)
    }
}