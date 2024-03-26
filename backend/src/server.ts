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