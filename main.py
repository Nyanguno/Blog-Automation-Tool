from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pymongo import MongoClient
from bson import ObjectId
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
from pydantic import BaseModel, Field

app = FastAPI()

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["blog_database"]
users_collection = db["users"]
blogs_collection = db["blogs"]

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Secret Key
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Function to Hash Password
def hash_password(password: str):
    return pwd_context.hash(password)

# Function to Verify Password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Pydantic Models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class User(BaseModel):
    id: str
    username: str
    email: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class BlogCreate(BaseModel):
    title: str
    content: str
    tags: List[str] = []

class BlogUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    tags: Optional[List[str]] = None

class Blog(BaseModel):
    id: str
    title: str
    content: str
    author: str
    tags: List[str] = []
    created_at: datetime
    updated_at: Optional[datetime] = None

# OAuth2 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# JWT Token Creation
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# User Authentication
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = users_collection.find_one({"username": token_data.username})
    if user is None:
        raise credentials_exception
    return user

# Helper function to convert MongoDB ObjectId to string
def serialize_id(item):
    item["id"] = str(item["_id"])
    del item["_id"]
    return item

# User Registration
@app.post("/signup", response_model=User)
async def create_user(user: UserCreate):
    # Check if user already exists
    if users_collection.find_one({"username": user.username}):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    # Create new user
    hashed_password = hash_password(user.password)
    user_data = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password,
        "created_at": datetime.utcnow()
    }
    result = users_collection.insert_one(user_data)
    created_user = users_collection.find_one({"_id": result.inserted_id})
    return serialize_id(created_user)

# User Login
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Create a blog post
@app.post("/add-blog/", response_model=Blog)
async def create_blog(blog: BlogCreate, current_user: dict = Depends(get_current_user)):
    blog_data = {
        "title": blog.title,
        "content": blog.content,
        "tags": blog.tags,
        "author": current_user["username"],
        "created_at": datetime.utcnow(),
        "updated_at": None
    }
    result = blogs_collection.insert_one(blog_data)
    created_blog = blogs_collection.find_one({"_id": result.inserted_id})
    return serialize_id(created_blog)

# Get all blogs
@app.get("/blogs/", response_model=List[Blog])
async def get_blogs():
    blogs = []
    for blog in blogs_collection.find():
        blogs.append(serialize_id(blog))
    return blogs

# Get a specific blog
@app.get("/blog/{blog_id}", response_model=Blog)
async def get_blog(blog_id: str):
    try:
        blog = blogs_collection.find_one({"_id": ObjectId(blog_id)})
        if blog:
            return serialize_id(blog)
        raise HTTPException(status_code=404, detail="Blog not found")
    except:
        raise HTTPException(status_code=400, detail="Invalid blog ID format")

# Update a blog
@app.put("/blog/{blog_id}", response_model=Blog)
async def update_blog(
    blog_id: str, 
    blog_update: BlogUpdate, 
    current_user: dict = Depends(get_current_user)
):
    try:
        blog = blogs_collection.find_one({"_id": ObjectId(blog_id)})
        if not blog:
            raise HTTPException(status_code=404, detail="Blog not found")
        
        if blog["author"] != current_user["username"]:
            raise HTTPException(status_code=403, detail="Not authorized to update this blog")
        
        # Build update data
        update_data = {}
        if blog_update.title:
            update_data["title"] = blog_update.title
        if blog_update.content:
            update_data["content"] = blog_update.content
        if blog_update.tags:
            update_data["tags"] = blog_update.tags
        
        update_data["updated_at"] = datetime.utcnow()
        
        blogs_collection.update_one(
            {"_id": ObjectId(blog_id)},
            {"$set": update_data}
        )
        
        updated_blog = blogs_collection.find_one({"_id": ObjectId(blog_id)})
        return serialize_id(updated_blog)
    except:
        raise HTTPException(status_code=400, detail="Invalid blog ID format")

# Delete a blog
@app.delete("/blog/{blog_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_blog(blog_id: str, current_user: dict = Depends(get_current_user)):
    try:
        blog = blogs_collection.find_one({"_id": ObjectId(blog_id)})
        if not blog:
            raise HTTPException(status_code=404, detail="Blog not found")
        
        if blog["author"] != current_user["username"]:
            raise HTTPException(status_code=403, detail="Not authorized to delete this blog")
            
        blogs_collection.delete_one({"_id": ObjectId(blog_id)})
        return None
    except:
        raise HTTPException(status_code=400, detail="Invalid blog ID format")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
