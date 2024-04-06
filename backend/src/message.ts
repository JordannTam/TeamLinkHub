import { 
    INVALID_PARAMETER,
    checkChannelId,
    dateInYyyyMmDdHhMmSs,
    pool,
    testChannelDmMsgId,
    testMessageFromUser,
    testNotChannelUser,
    testUserIsOwner 
} from './util'

/********************
 * Message Function *
 ********************/

/* 
    method: POST
    Parameters: { token, channel_id, message }
    Return Type: { message_id }
    path: /message/send

    InputError when:
        channel_id does not refer to a valid channel
        length of message is less than 1 or over 1000 characters
    AccessError when:
        channel_id is valid and the authorised user is not a member of the channel
*/
export const messageSend = async (req: any, res: any) => {
    try {
        const auth_user_id = res.locals.user.auth_user_id
        const channel_id = req.body.channel_id
        const message = req.body.message
        // channel_id does not refer to a valid channel
        await checkChannelId(res, channel_id)
        // length of message is less than 1 or over 1000 characters
        if (message < 1 || message > 1000) {
            res.status(INVALID_PARAMETER)
            throw new Error(`length of message is less than 1 or over 1000 characters`)
        }
        // channel_id is valid and the authorised user is not a member of the channel
        await testNotChannelUser(res, auth_user_id, channel_id)
        const dateNow = new Date(Date.now())
        const query = "INSERT INTO messages (channel_id, auth_user_id, message, react, time_sent) values ($1, $2, $3, $4, $5) RETURNING message_id;"
        const values = [ channel_id, auth_user_id, message, 0, dateInYyyyMmDdHhMmSs(dateNow) ]
        const qRes = await pool.query(query, values)
        res.json(qRes.rows[0])
    } catch(err) {
        return res.send(`${err}`)
    }
}


/* 
    method: PUT
    Parameters: { token, message_id, message }
    Return Type: {}
    path: /message/edit

    InputError when any of:
        length of message is over 1000 characters
        message_id does not refer to a valid message within a channel/DM that the authorised user has joined
    AccessError when message_id refers to a valid message in a joined channel/DM and none of the following are true:
        the message was sent by the authorised user making this request
        the authorised user has owner permissions in the channel/DM
*/
export const messageEdit = async (req: any, res: any) => {
    try {
        const message_id = req.body.message_id
        const message = req.body.message
        const auth_user_id = res.locals.user.auth_user_id
        console.log(message_id, auth_user_id);
        
        // length of message is less than 1 or over 1000 characters
        if (message < 1 || message > 1000) {
            res.status(INVALID_PARAMETER)
            throw new Error(`length of message is less than 1 or over 1000 characters`)
        }
        // message_id does not refer to a valid message within a channel/DM that the authorised user has joined
        await testChannelDmMsgId(res, message_id, auth_user_id)
        // get the channel_id of the message
        await testMessageFromUser(res, auth_user_id, message_id)
        await testUserIsOwner(res, auth_user_id, message_id)

        const query = "UPDATE messages SET message = $1;"
        const values = [ message ]
        await pool.query(query, values)
        res.json({})
    } catch(err) {
        return res.send(`${err}`)
    }
}

/*
    method: DELETE
    Parameters: { token, message_id }
    Return Type: {}
    path: message/remove

    InputError when:
        message_id does not refer to a valid message within a channel/DM that the authorised user has joined
    AccessError when message_id refers to a valid message in a joined channel/DM and none of the following are true:
        the message was sent by the authorised user making this request
        the authorised user has owner permissions in the channel/DM
*/
export const messageRemove = async (req: any, res: any) => {
    try {
        const message_id = req.query.message_id
        const auth_user_id = res.locals.user.auth_user_id
        await testChannelDmMsgId(res, message_id, auth_user_id)
        await testMessageFromUser(res, auth_user_id, message_id)
        await testUserIsOwner(res, auth_user_id, message_id)
        const query = "DELETE FROM messages WHERE message_id = $1;"
        const values = [ message_id ]
        await pool.query(query, values)
        res.json({})

    } catch(err) {
        return res.send(`${err}`)
    }
}
