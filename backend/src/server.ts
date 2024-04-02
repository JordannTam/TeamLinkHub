import express from "express";
import cors from "cors"
import 'dotenv/config'
import { 
    authenticateToken, 
    generateAccessToken,
    auth_login,
    usersAll,
    auth_register,
    userProfile,
    userSetName,
    userSetEmail,
    userSetHandle,
    channelCreate,
    channelsList,
    channelsListAll,
    channelDetails,
    channelJoin,
    channelInvite,
    channelLeave,
    channelAddowner,
    messageSend,
    channelRemoveowner,
    messageEdit,
    channelMessages,
    messageRemove, 
} 
    from "./service";

const app = express()
const port = 3000

app.use(express.json())
app.use(cors())


const posts = [
    {
        email: 'jordan@test.com',
        title: 'Post 1'
    },
    {
        email: 'jim@test.com',
        title: 'Post 2'
    }
]


app.get('/posts', authenticateToken, (req, res) => {    
    res.json(posts.filter((post) => post.email === res.locals.user.email))
})

app.post(`/auth/login`, (req, res) => {
    // Auth User
    auth_login(req, res)
})

app.post(`/auth/register`, (req, res) => {
    auth_register(req, res)
})

app.post(`/auth/logout`, authenticateToken, (req, res) => {
    //
    // TODO
    //

})

app.post(`/channels/create`, authenticateToken, (req, res) => {
    channelCreate(req, res)
})

app.get(`/channels/list`, authenticateToken, (req, res) => {
    channelsList(req, res)
})

app.get(`/channels/listall`, authenticateToken, (req, res) => {
    channelsListAll(req, res)
})

app.get(`/channel/details`, authenticateToken, (req, res) => {
    channelDetails(req, res)
})

app.post(`/channel/join`, authenticateToken, (req, res) => {
    channelJoin(req, res)
})

app.post(`/channel/invite`, authenticateToken, (req, res) => {
    channelInvite(req, res)
})

app.get(`/channel/messages`, authenticateToken, (req, res) => {
    channelMessages(req, res)
})

app.post(`/channel/leave`, authenticateToken, (req, res) => {
    channelLeave(req, res)
})

app.post(`/channel/addowner`, authenticateToken, (req, res) => {
    channelAddowner(req, res)
})

app.post(`/channel/removeowner`, authenticateToken, (req, res) => {
    channelRemoveowner(req, res)
})

app.post(`/message/send`, authenticateToken, (req, res) => {
    messageSend(req, res)
})

app.put(`/message/edit`, authenticateToken, (req, res) => {
    messageEdit(req, res)
})

app.delete(`/message/remove`, authenticateToken, (req, res) => {
    messageRemove(req, res)
})

app.get(`/users/all`, authenticateToken, (req, res) => {
    usersAll(req, res)
})

app.get(`/user/profile`, authenticateToken, (req, res) => {
    userProfile(req, res)
})

app.put(`/user/profile/setname`, authenticateToken, (req, res) => {
    userSetName(req, res)
})

app.put(`/user/profile/setemail`, authenticateToken, (req, res) => {
    userSetEmail(req, res)
})

app.put(`/user/profile/sethandle`, authenticateToken, (req, res) => {
    userSetHandle(req, res)
})


app.listen(port, () => {
    console.log(`Server is up and running on ${port} ...`);
})