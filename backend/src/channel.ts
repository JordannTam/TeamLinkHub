
import { 
    ACCESS_ERROR,
    INVALID_PARAMETER,
    INVALID_TOKEN,
    checkChannelId,
    checkUserId,
    getPermissionId,
    isPublicChannel,
    pool,
    testHasChannelUser,
    testNotChannelUser,
    validChannelName 
} from './util'

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
        return res.send(`${err}`)
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
        return res.send(`${err}`)
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
        return res.send(`${err}`)
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
        await testHasChannelUser(res, channel_id, auth_user_id)
        const query = "SELECT c.name, c.is_public, json_agg(json_build_object('user_id', cu.auth_user_id, 'is_owner', cu.is_owner, 'username', u.username, 'name_first', name_first, 'name_last', name_last, 'email', email, 'permission_id', permission_id, 'img', img )) AS members FROM channels c JOIN channel_user cu ON c.channel_id = cu.channel_id JOIN users u ON cu.auth_user_id = u.auth_user_id WHERE c.channel_id = $1 GROUP BY c.channel_id"
        const values = [ channel_id ]
        const qRes = await pool.query(query, values)
        res.json(qRes.rows[0])
    } catch(err) { 
        res.status(INVALID_PARAMETER)
        return res.send(`${err}`)
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
        await testHasChannelUser(res, auth_user_id, channel_id)

        const permission_id = await getPermissionId(auth_user_id)
        const is_public = await isPublicChannel(channel_id)
        if (!is_public && permission_id === 2 && testNotChannelUser(res, auth_user_id, channel_id)) {
            res.status(ACCESS_ERROR)
            throw new Error(`channel_id refers to a channel that is private`)
        }

        const query = "INSERT INTO channel_user (channel_id, auth_user_id, is_owner) VALUES ($1, $2, $3);"
        const values = [ channel_id, auth_user_id, false]
        await pool.query(query, values)
        res.json({})
    } catch(err) {
        return res.send(`${err}`)
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
        await testHasChannelUser(res, target_u_id, channel_id)
        // channel_id is valid and the authorised user is not a member of the channel
        await testNotChannelUser(res, user.auth_user_id, channel_id)

        const query = "INSERT INTO channel_user (channel_id, auth_user_id, is_owner) VALUES ($1, $2, $3);"
        const values = [ channel_id, target_u_id, false ]
        pool.query(query, values)
        res.json({})

    } catch(err) {
        return res.send(`${err}`)
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
        return res.send(`${err}`)
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
        await testNotChannelUser(res, target_u_id, channel_id)
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
        return res.send(`${err}`)
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
        await testNotChannelUser(res, target_u_id, channel_id)
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
        return res.send(`${err}`)
    }
}

/*
    method: GET
    Parameters: { token, channel_id, start }
    Return Type: { messages, start, end }

    InputError when any of:
        channel_id does not refer to a valid channel
        start is greater than the total number of messages in the channel
    AccessError when:
        channel_id is valid and the authorised user is not a member of the channel
*/

export const channelMessages = async (req: any, res: any) => {
    try {
        const start = parseInt(req.query.start)
        const channel_id = parseInt(req.query.channel_id)
        const auth_user_id = res.locals.user.auth_user_id
        //channel_id does not refer to a valid channel
        await checkChannelId(res, channel_id)

        //start is greater than the total number of messages in the channel
        const q_input_error_1 = "SELECT channel_id, COUNT(*) AS count FROM messages WHERE channel_id = $1 GROUP BY channel_id;"
        const v_input_error_1 = [ channel_id ]
        const res_input_error_1 = await pool.query(q_input_error_1, v_input_error_1)
        if (res_input_error_1.rows[0].count < start) {
            res.status(INVALID_PARAMETER)
            throw new Error(`start is greater than the total number of messages in the channel`)
        }
        let end = res_input_error_1.rows[0].count < 50 ? -1 : start + 50

        //channel_id is valid and the authorised user is not a member of the channel
        await testNotChannelUser(res, auth_user_id, channel_id)
        
        // Return Messages
        const query = "SELECT message AS message FROM messages WHERE channel_id = $1 ORDER BY time_sent DESC;"
        const values = [ channel_id ]
        const qRes = await pool.query(query, values)
        const messages = qRes.rows.map((r) => r.message).splice(start)
        res.json({ messages: messages, start: start, end: end})

    } catch(err) {
        return res.send(`${err}`)
    }
}
