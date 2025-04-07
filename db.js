const {PrismaClient} = require('@prisma/client');
const prisma = new PrismaClient();

async function getUsers(){
    return await prisma.user.findMany()
}

async function getUserByUsername(username){
    return await prisma.user.findUnique({
        where:{
            username: username
        },
        include:{
            posts: true,
            comments: true,
            like: true
        }
    })
}

async function getUserByEmail(email){
    return await prisma.user.findUnique({
        where:{
            email: email
        },
        include:{
            posts: true,
            comments: true,
            Like: true
        }
    })
}

async function createUser(username, email, password){
    await prisma.user.create({
        data:{
            username: username,
            email: email,
            password: password
        }
    })
}

async function getUserLikedPosts(userId){
    const user = await prisma.user.findUnique({
        where:{
            id: userId
        },
        select:{
            like: true
        }
    })
    return user.like
}

async function likePost(userId, postId){
    const like = await prisma.like.create({
        data:{
            userId: userId,
            postId: postId
        }
    })
    await prisma.post.update({
        where:{
            id: postId
        },
        data:{
            likes: {increment: 1}
        }
    })
    return like;
}

async function dislikePost(userId, postId, likeId){
    await prisma.like.delete({
        where:{
            id: likeId
        }
    })
    await prisma.post.update({
        where:{
            id: postId
        },
        data:{
            likes: {decrement: 1}
        }
    })
}

async function createComment(content, userId, postId){
    await prisma.comment.create({
        data:{
            content: content,
            author:{
                connect:{
                    id: userId
                }
            },
            parentPost:{
                connect:{
                    id: postId
                }
            }
        }
    })
}

async function getPosts(){
    return await prisma.post.findMany({
        include:{
            author: true,
            comments: true
        },
        orderBy:{
            createdAt: 'desc'
        }
    });
}

async function getPost(postId){
    return await prisma.post.findUnique({
        where:{
            id: postId
        },
        include:{
            author: true,
            comments: {
                include:{
                    author: true,
                    parentPost: true
                }
            }
        },
    });
}

async function createPost(title, content, authorId, postStatus){
    await prisma.post.create({
        data:{
            title: title,
            content: content,
            author:{
                connect:{
                    id: authorId
                }
            },
            postStatus: postStatus
        }
    })
}



module.exports={
    getUsers,
    getUserByUsername,
    getUserByEmail,
    createUser,
    getPosts,
    createPost,
    likePost,
    dislikePost,
    getUserLikedPosts,
    createComment,
    getPost
}