from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)
db = client["foodieweb"]

users_collection = db["users"]
roles_collection = db["roles"]
permissions_collection = db["permissions"]
role_permissions_collection = db["role_permissions"]
