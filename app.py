# app.py
from flask import Flask, request, jsonify, send_from_directory
from flask_pymongo import PyMongo
from flask_cors import CORS
from slugify import slugify 
import bcrypt
import jwt
import requests
import locale
from datetime import date, datetime, timedelta
import re
import os
from functools import wraps
from werkzeug.utils import secure_filename
import time
from bson.objectid import ObjectId

# -------------------------
# Config
# -------------------------
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "https://foodiestore.vercel.app"}})


MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://foodieweb:FoodieWeb1!@cluster0.cqqlapf.mongodb.net/FoodieWeb?retryWrites=true&w=majority")
SECRET_KEY = os.getenv("SECRET_KEY", "change_me_in_prod")

app.config["MONGO_URI"] = MONGO_URI
mongo = PyMongo(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

EMAIL_REGEX = r"^[\w\.-]+@[\w\.-]+\.\w+$"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

# ---------------------------
# Helpers
# ---------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = data
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception:
            return jsonify({"error": "Token invalid"}), 401
        return f(*args, **kwargs)
    return decorated

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def rename_file(filename):
    ext = filename.rsplit(".", 1)[1].lower()
    return f"dish_{int(time.time())}.{ext}"

# ---------------------------
# Auth Routes
# ---------------------------
@app.route("/api/register", methods=["POST"])
def register():
    data = request.json or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    address = data.get("address", "")
    phone = data.get("phone", "")
    password = data.get("password", "")
    

    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400
    if len(username) < 3 or not username.replace(" ", "").isalpha():
        return jsonify({"error": "Username must be letters and spaces only"}), 400
    if not re.match(EMAIL_REGEX, email):
        return jsonify({"error": "Invalid email format"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    if not re.match(password_regex, password):
        return jsonify({"error": "Password must contain uppercase, lowercase, number, and special character"}), 400
    if mongo.db.users.find_one({"email": email}):
        return jsonify({"error": "User already exists"}), 400

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    mongo.db.users.insert_one({
        "username": username,
        "email": email,
        "phone": phone,
        "address": address,
        "status": "active",
        "role": "user",
        "password": hashed_pw,
        "created_at": datetime.utcnow(),
        "updated_at": None,
        "deleted_at": None
    })

    new_user = mongo.db.users.find_one({"email": email})

    return jsonify({
    "message": "User registered successfully",
    "user": {
        "id": str(new_user["_id"]),
        "username": new_user["username"],
        "email": new_user["email"],
        "role": new_user.get("role", "user")
    }
}), 201

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = mongo.db.users.find_one({"email": email, "status": "active" })
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
        return jsonify({"error": "Invalid credentials"}), 401

    token_payload = {
        "user_id": str(user["_id"]),
        "email": user["email"],
        "username": user["username"],
        "exp": datetime.utcnow() + timedelta(days=1),
        "role": user.get("role", "user")
    }
    token = jwt.encode(token_payload, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        }
    }), 200

# ---------------------------
# User Routes
# ---------------------------
@app.route("/api/admin/users", methods=["GET"])
@token_required 
def list_users():
    users = list(mongo.db.users.find({}, {"password": 0}))
    for u in users:
        u["_id"] = str(u["_id"])
    return jsonify(users), 200


# ----------------------------
# Get all customers
# ----------------------------
@app.route("/api/customers", methods=["GET"])
def get_customers():
    try:
        # Only users (role=user)
        customers = list(mongo.db.users.find({"role": "user"}))
        
        # Optional: calculate total orders
        orders = list(mongo.db.orders.find())
        
        for customer in customers:
            customer["_id"] = str(customer["_id"])
            customer["name"] = customer.get("username", "")
            customer["joinedDate"] = (
                customer["created_at"].strftime("%Y-%m-%d")
                if "created_at" in customer and isinstance(customer["created_at"], datetime)
                else ""
            )
            customer["totalOrders"] = sum(
                1 for order in orders if order.get("user_id") == customer["_id"]
            )
        return jsonify(customers)
    except Exception as e:
        print(e)
        return jsonify({"error": "Failed to fetch customers"}), 500


# ----------------------------
# Delete customer
# ----------------------------
@app.route("/api/customers/<id>", methods=["DELETE"])
def delete_customer(id):
    try:
        result = mongo.db.users.delete_one({"_id": ObjectId(id), "role": "user"})
        if result.deleted_count == 0:
            return jsonify({"error": "Customer not found"}), 404
        return jsonify({"message": "Customer deleted successfully"})
    except Exception as e:
        print(e)
        return jsonify({"error": "Failed to delete customer"}), 500


# ----------------------------
# Update customer
# ----------------------------
@app.route("/api/customers/<id>", methods=["PUT"])
def update_customer(id):
    data = request.json
    try:
        update_data = {
            "username": data.get("name"),
            "email": data.get("email"),
            "address": data.get("address", ""),
            "status": data.get("status", "active"),
        }
        result = mongo.db.users.update_one(
            {"_id": ObjectId(id), "role": "user"},
            {"$set": update_data}
        )
        if result.matched_count == 0:
            return jsonify({"error": "Customer not found"}), 404
        return jsonify({"message": "Customer updated successfully"})
    except Exception as e:
        print(e)
        return jsonify({"error": "Failed to update customer"}), 500

# ---------------------------
# Serve uploaded images
# ---------------------------
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# ---------------------------
# Dish Routes with Audit + Soft Delete
# ---------------------------
@app.route("/api/dishes", methods=["POST"])
@token_required
def create_dish():
    
    title = request.form.get("title")
    price = request.form.get("price")
    day = request.form.get("day")
    img_file = request.files.get("img")
    
    print(request.user["user_id"])

    if not title or not price or not day:
        return jsonify({"error": "Title, price, and day are required"}), 400

    img_url = ""
    if img_file:
        ext = img_file.filename.rsplit(".", 1)[-1].lower()
        filename = f"dish_{int(datetime.utcnow().timestamp())}.{ext}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        img_file.save(filepath)
        img_url = f"/{UPLOAD_FOLDER}/{filename}"

    dish = {
        "title": title,
        "price": float(price),
        "day": day,
        "img": img_url,
        "created_by": request.user["user_id"],   # <-- Save user _id
        "created_at": datetime.utcnow(),
        "updated_by": None,
        "updated_at": None,
        "deleted_by": None,
        "deleted_at": None
    }

    mongo.db.dishes.insert_one(dish)
    return jsonify({"message": "Dish added successfully"}), 201


@app.route("/api/dishes", methods=["GET"])
def get_dishes():
    
    dishes = list(mongo.db.dishes.find({"deleted_at": None}).sort("created_at", -1))
    for d in dishes:
        d["_id"] = str(d["_id"])
        if "img" in d:
            d["img"] = request.host_url.rstrip("/") + d["img"]
            
    return jsonify(dishes), 200


@app.route("/api/dishes/<dish_id>", methods=["PUT"])
@token_required
def update_dish(dish_id):
    try:
        dish_oid = ObjectId(dish_id)
    except Exception:
        return jsonify({"error": "Invalid dish ID"}), 400

    dish = mongo.db.dishes.find_one({"_id": dish_oid, "deleted_at": None})
    if not dish:
        return jsonify({"error": "Dish not found"}), 404

    title = request.form.get("title") or dish["title"]
    price = request.form.get("price") or dish["price"]
    day = request.form.get("day") or dish["day"]
    img_file = request.files.get("img")

    img_url = dish.get("img", "")
    if img_file:
        ext = img_file.filename.rsplit(".", 1)[-1].lower()
        filename = f"dish_{int(datetime.utcnow().timestamp())}.{ext}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        img_file.save(filepath)
        img_url = f"/{UPLOAD_FOLDER}/{filename}"

    mongo.db.dishes.update_one(
        {"_id": dish_oid},
        {"$set": {
            "title": title,
            "price": float(price),
            "day": day,
            "img": img_url,
            "updated_by": request.user["email"],
            "updated_at": datetime.utcnow()
        }}
    )

    return jsonify({"message": "Dish updated successfully"}), 200


@app.route("/api/dishes/<dish_id>", methods=["DELETE"])
@token_required
def delete_dish(dish_id):
    try:
        dish_oid = ObjectId(dish_id)
    except Exception:
        return jsonify({"error": "Invalid dish ID"}), 400

    dish = mongo.db.dishes.find_one({"_id": dish_oid, "deleted_at": None})
    if not dish:
        return jsonify({"error": "Dish not found or already deleted"}), 404

    mongo.db.dishes.update_one(
        {"_id": dish_oid},
        {"$set": {
            "deleted_by": request.user["email"],
            "deleted_at": datetime.utcnow()
        }}
    )

    return jsonify({"message": "Dish soft deleted successfully"}), 200


# Orders
@app.route("/api/orders", methods=["GET"])
def get_orders():
    # Sort by 'created_at' in descending order (-1 means newest first)
    orders = list(mongo.db.orders.find().sort("created_at", -1))
    
    for order in orders:
        order["_id"] = str(order["_id"])
        
    return jsonify(orders), 200


@app.route("/api/orders/update/<id>", methods=["PUT"])
def update_order_status(id):
    data = request.get_json()
    status = data.get("status", "")
    mongo.db.orders.update_one({"_id": ObjectId(id)}, {"$set": {"status": status}})
    return jsonify({"message": "Status updated"}), 200

@app.route("/api/orders/delete/<id>", methods=["DELETE"])
def delete_order(id):
    mongo.db.orders.delete_one({"_id": ObjectId(id)})
    return jsonify({"message": "Order deleted"}), 200

# Frontend
# Frontend route for today's dishes
@app.route("/api/fdishes", methods=["GET"])
def get_fdishes():
        # Set locale to U.S. English for consistent weekday names
    today = date.today() 
    day = today.strftime("%A")
    # Convert ObjectId to string for JSON serialization
    for d in dishes:
        d["_id"] = str(d["_id"])
        if "img" in d:
            d["img"] = request.host_url.rstrip("/") + d["img"]


    # Return both dishes and today name
    return jsonify({"dishes": dishes, "today": day}), 200

# ---------- CART endpoints (add/replace in app.py) ----------
from bson.objectid import ObjectId
from datetime import datetime, date

@app.route("/api/cart", methods=["GET"])
@token_required
def get_cart():
    user_id = request.user.get("user_id")
    if not user_id:
        return jsonify({"cart": [], "total": 0})
    cart_doc = mongo.db.carts.find_one({"user_id": user_id, "checked_out": False})
    if not cart_doc:
        return jsonify({"cart": [], "total": 0})
    # Normalize items for response
    items = cart_doc.get("items", [])
    # Attach absolute URL for images if needed
    for it in items:
        if it.get("img") and it["img"].startswith("/"):
            it["img"] = request.host_url.rstrip("/") + it["img"]
    return jsonify({"items": items, "total": cart_doc.get("total", 0)}), 200

@app.route("/api/cart", methods=["POST"])
@token_required
def add_to_cart():
    user_id = request.user.get("user_id")
    data = request.get_json() or {}
    dish_id = data.get("dish_id")
    quantity = int(data.get("quantity", 1))

    if not dish_id:
        return jsonify({"error": "dish_id is required"}), 400

    # validate dish
    try:
        dish = mongo.db.dishes.find_one({"_id": ObjectId(dish_id), "deleted_at": None})
    except Exception:
        return jsonify({"error": "Invalid dish id"}), 400

    if not dish:
        return jsonify({"error": "Dish not found"}), 404

    # enforce today's dish
    today_name = date.today().strftime("%A").lower()
    if (dish.get("day") or "").lower() != today_name:
        return jsonify({"error": "You can only add today's dishes"}), 400

    # get or create cart
    cart_doc = mongo.db.carts.find_one({"user_id": user_id, "checked_out": False})
    if not cart_doc:
        cart_doc = {
            "user_id": user_id,
            "items": [],
            "total": 0.0,
            "checked_out": False,
            "created_at": datetime.utcnow()
        }
        mongo.db.carts.insert_one(cart_doc)
        cart_doc = mongo.db.carts.find_one({"user_id": user_id, "checked_out": False})

    # update items array: find if dish present
    items = cart_doc.get("items", [])
    found = False
    for it in items:
        if str(it.get("dish_id")) == str(dish_id):
            it["quantity"] = int(it.get("quantity", 0)) + quantity
            found = True
            break
    if not found:
        items.append({
            "dish_id": str(dish["_id"]),
            "title": dish["title"],
            "price": float(dish["price"]),
            "quantity": quantity,
            "img": dish.get("img", ""),
            "day": dish.get("day", "")
        })

    total = sum([it["price"] * it["quantity"] for it in items])

    mongo.db.carts.update_one(
        {"user_id": user_id, "checked_out": False},
        {"$set": {"items": items, "total": total}}
    )

    # ensure returned image URL absolute
    for it in items:
        if it.get("img", "").startswith("/"):
            it["img"] = request.host_url.rstrip("/") + it["img"]

    return jsonify({"message": "Item added to cart", "cart": {"items": items, "total": total}}), 200

@app.route("/api/cart", methods=["PUT"])
@token_required
def update_cart_item():
    # body: { dish_id, quantity }
    user_id = request.user.get("user_id")
    data = request.get_json() or {}
    dish_id = data.get("dish_id")
    quantity = int(data.get("quantity", 0))

    if not dish_id:
        return jsonify({"error": "dish_id is required"}), 400

    cart_doc = mongo.db.carts.find_one({"user_id": user_id, "checked_out": False})
    if not cart_doc:
        return jsonify({"error": "Cart not found"}), 404

    items = cart_doc.get("items", [])
    new_items = []
    for it in items:
        if str(it.get("dish_id")) == str(dish_id):
            if quantity <= 0:
                # skip = remove
                continue
            else:
                it["quantity"] = quantity
                new_items.append(it)
        else:
            new_items.append(it)

    total = sum([it["price"] * it["quantity"] for it in new_items])
    mongo.db.carts.update_one({"user_id": user_id, "checked_out": False}, {"$set": {"items": new_items, "total": total}})

    for it in new_items:
        if it.get("img", "").startswith("/"):
            it["img"] = request.host_url.rstrip("/") + it["img"]

    return jsonify({"message": "Cart updated", "cart": {"items": new_items, "total": total}}), 200

@app.route("/api/cart/<dish_id>", methods=["DELETE"])
@token_required
def remove_cart_item(dish_id):
    user_id = request.user.get("user_id")
    cart_doc = mongo.db.carts.find_one({"user_id": user_id, "checked_out": False})
    if not cart_doc:
        return jsonify({"error": "Cart not found"}), 404

    items = [it for it in cart_doc.get("items", []) if str(it.get("dish_id")) != str(dish_id)]
    total = sum([it["price"] * it["quantity"] for it in items])
    mongo.db.carts.update_one({"user_id": user_id, "checked_out": False}, {"$set": {"items": items, "total": total}})
    for it in items:
        if it.get("img", "").startswith("/"):
            it["img"] = request.host_url.rstrip("/") + it["img"]
    return jsonify({"message": "Removed", "cart": {"items": items, "total": total}}), 200

@app.route("/api/checkout", methods=["POST"])
def checkout():
    try:
        # --- Verify token ---
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401

        token = auth_header.split(" ")[1]
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        # --- Get order data ---
        data = request.json or {}
        user_id = data.get("user_id")
        user_info = data.get("user_info")
        items = data.get("items", [])
        total = data.get("total", 0)

        if not user_id or not items:
            return jsonify({"error": "Invalid checkout data"}), 400

        # --- Create order object ---
        order = {
            "user_id": user_id,
            "user_info": user_info,
            "items": items,
            "total": total,
            "status": "pending",
            "created_at": datetime.utcnow(),
        }

        # --- Insert into MongoDB ---
        result = mongo.db.orders.insert_one(order)
        order_id = str(result.inserted_id)

        # --- Return order info for Thank You Page ---
        return jsonify({
            "message": "Order placed successfully!",
            "order_id": order_id,
            "status": "pending",
            "total": total
        }), 200

    except Exception as e:
        print("Checkout Error:", e)
        return jsonify({"error": "Server error"}), 500
    
    
@app.route("/api/orders/<order_id>", methods=["GET"])
def get_order_by_id(order_id):
    try:
        # Find order by MongoDB ObjectId
        order = mongo.db.orders.find_one({"_id": ObjectId(order_id)})

        if not order:
            return jsonify({"error": "Order not found"}), 404

        # Convert ObjectId to string for JSON response
        order["_id"] = str(order["_id"])

        return jsonify({"order": order}), 200

    except Exception as e:
        print("Track Order Error:", e)
        return jsonify({"error": "Invalid or expired Order ID"}), 500


@app.route("/api/user/<user_id>", methods=["GET"])
def get_user(user_id):
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401

        token = auth_header.split(" ")[1]
        jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404

        user["_id"] = str(user["_id"])
        return jsonify({
            "user": {
                "id": user["_id"],
                "username": user["username"],
                "email": user["email"],
                "address": user.get("address", ""),
                "phone": user.get("phone", ""),
                "role": user.get("role", "user"),
            }
        }), 200

    except Exception as e:
        print("Get User Error:", e)
        return jsonify({"error": "Server error"}), 500


@app.route("/api/user/<user_id>", methods=["PUT"])
@token_required
def update_user(user_id):
    try:
        token_user_id = request.user.get("user_id")
        if token_user_id != user_id:
            return jsonify({"error": "Forbidden: Cannot update other user's profile"}), 403

        data = request.json or {}
        update_data = {}

        # Optional fields to update
        if "username" in data:
            username = data["username"].strip()
            if len(username) < 3 or not username.replace(" ", "").isalpha():
                return jsonify({"error": "Username must be letters and spaces only"}), 400
            update_data["username"] = username

        if "email" in data:
            email = data["email"].strip().lower()
            if not re.match(EMAIL_REGEX, email):
                return jsonify({"error": "Invalid email format"}), 400
            # Ensure no duplicate email
            existing_user = mongo.db.users.find_one({"email": email, "_id": {"$ne": ObjectId(user_id)}})
            if existing_user:
                return jsonify({"error": "Email already in use"}), 400
            update_data["email"] = email

        if "phone" in data:
            update_data["phone"] = data["phone"].strip()

        if "address" in data:
            update_data["address"] = data["address"].strip()

        if not update_data:
            return jsonify({"error": "No valid fields to update"}), 400

        update_data["updated_at"] = datetime.utcnow()

        result = mongo.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )

        if result.matched_count == 0:
            return jsonify({"error": "User not found"}), 404

        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        user["_id"] = str(user["_id"])

        return jsonify({
            "message": "Profile updated successfully",
            "user": {
                "id": user["_id"],
                "username": user["username"],
                "email": user["email"],
                "address": user.get("address", ""),
                "phone": user.get("phone", ""),
                "role": user.get("role", "user")
            }
        }), 200

    except Exception as e:
        print("Update User Error:", e)
        return jsonify({"error": "Server error"}), 500
    

# -------------------------
# 🏷️ Blog Categories Routes
# -------------------------

@app.route("/api/categories", methods=["GET"])
def get_categories():
    categories = list(mongo.db.categories.find())
    for cat in categories:
        cat["_id"] = str(cat["_id"])
    return jsonify(categories), 200


@app.route("/api/categories", methods=["POST"])
def add_category():
    data = request.json or {}
    name = data.get("name", "").strip()

    if not name:
        return jsonify({"error": "Category name is required"}), 400

    # Check for duplicates
    if mongo.db.categories.find_one({"name": {"$regex": f"^{name}$", "$options": "i"}}):
        return jsonify({"error": "Category already exists"}), 409

    slug = name.lower().replace(" ", "-")

    mongo.db.categories.insert_one({
        "name": name,
        "slug": slug,
        "created_at": datetime.utcnow()
    })
    return jsonify({"message": "Category added successfully"}), 201


@app.route("/api/categories/<id>", methods=["PUT"])
def update_category(id):
    data = request.json or {}
    name = data.get("name", "").strip()

    if not name:
        return jsonify({"error": "Category name is required"}), 400

    category = mongo.db.categories.find_one({"_id": ObjectId(id)})
    if not category:
        return jsonify({"error": "Category not found"}), 404

    slug = name.lower().replace(" ", "-")

    mongo.db.categories.update_one(
        {"_id": ObjectId(id)},
        {"$set": {"name": name, "slug": slug}}
    )
    return jsonify({"message": "Category updated successfully"}), 200


@app.route("/api/categories/<id>", methods=["DELETE"])
def delete_category(id):
    result = mongo.db.categories.delete_one({"_id": ObjectId(id)})
    if result.deleted_count == 0:
        return jsonify({"error": "Category not found"}), 404
    return jsonify({"message": "Category deleted successfully"}), 200



# ---------------------------
# 📝 Blog Posts Routes
# ---------------------------

@app.route("/api/blog-posts", methods=["POST"])
@token_required
def create_blog_post():
    """
    Create a new blog post.
    Requires Authorization header: Bearer <token>
    """
    title = request.form.get("title")
    content = request.form.get("content")
    category_id = request.form.get("category")
    img_file = request.files.get("image")

    if not title or not content or not category_id:
        return jsonify({"error": "Title, content, and category are required"}), 400

    # Handle image upload
    image_url = ""
    if img_file:
        if "." not in img_file.filename or img_file.filename.rsplit(".", 1)[1].lower() not in {"png","jpg","jpeg","webp"}:
            return jsonify({"error": "Invalid image format"}), 400
        filename = secure_filename(f"blog_{int(datetime.utcnow().timestamp())}.{img_file.filename.rsplit('.',1)[1].lower()}")
        img_file.save(os.path.join(UPLOAD_FOLDER, filename))
        image_url = f"/{UPLOAD_FOLDER}/{filename}"

    # Create slug
    slug = slugify(title)
    existing = mongo.db.blog_posts.find_one({"slug": slug})
    if existing:
        slug += f"-{int(datetime.utcnow().timestamp())}"

    post = {
        "title": title,
        "slug": slug,
        "content": content,
        "category": ObjectId(category_id),
        "image": image_url,
        "author": request.user.get("user_id"),
        "created_at": datetime.utcnow(),
        "updated_at": None
    }

    mongo.db.blog_posts.insert_one(post)
    return jsonify({"message": "Post created successfully"}), 201


# 🟨 Get all blog posts
@app.route("/api/blogposts", methods=["GET"])
def get_blog_posts():
    posts = list(mongo.db.blog_posts.find().sort("created_at", -1))
    for post in posts:
        post["_id"] = str(post["_id"])
        
        # Fetch category name
        category = mongo.db.categories.find_one({"_id": ObjectId(post["category"])})
        if category:
            post["category"] = {"_id": str(category["_id"]), "name": category["name"]}
        else:
            post["category"] = None
    return jsonify(posts)

@app.route("/api/blogposts/<post_id>", methods=["GET"])
def get_blog_post(post_id):
    try:
        post = mongo.db.blog_posts.find_one({"_id": ObjectId(post_id)})
        if not post:
            return jsonify({"error": "Post not found"}), 404

        # Convert ObjectId and prepare response
        post["_id"] = str(post["_id"])
        post["category"] = str(post["category"]) if "category" in post else None

        return jsonify(post), 200

    except Exception as e:
        print("Error fetching post:", e)
        return jsonify({"error": "Invalid post ID"}), 400
    
@app.route("/api/blogposts/<id>", methods=["PUT"])
def update_blog(id):
    try:
        print("Updating blog with ID:", id)
        blog = mongo.db.blog_posts.find_one({"_id": ObjectId(id)})

        if not blog:
            return jsonify({"message": "Blog not found"}), 404

        title = request.form.get("title")
        category = request.form.get("category")
        content = request.form.get("content")

        update_data = {}

        if title:
            update_data["title"] = title
        if category:
            update_data["category"] = category
        if content:
            update_data["content"] = content

        # ✅ Handle image upload
        if "image" in request.files:
            image = request.files["image"]
            if image:
                filename = secure_filename(image.filename)
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                image_path = os.path.join(UPLOAD_FOLDER, filename)
                image.save(image_path)
                update_data["image"] = f"/uploads/{filename}"

        # ✅ Update in MongoDB
        mongo.db.blog_posts.update_one(
            {"_id": ObjectId(id)},
            {"$set": update_data}
        )

        # ✅ Fetch updated document
        updated_blog = mongo.db.blog_posts.find_one({"_id": ObjectId(id)})

        return jsonify({
            "message": "Blog updated successfully",
            "blog": {
                "_id": str(updated_blog["_id"]),
                "title": updated_blog.get("title"),
                "category": updated_blog.get("category"),
                "content": updated_blog.get("content"),
                "image": updated_blog.get("image", None)
            }
        }), 200

    except Exception as e:
        print("Error updating blog:", e)
        return jsonify({"message": "Server error", "error": str(e)}), 500

# 🟥 Delete post
@app.route("/api/posts/<post_id>", methods=["DELETE"])
@token_required
def delete_post(current_user, post_id):
    post = mongo.db.posts.find_one({"_id": ObjectId(post_id)})
    if not post:
        return jsonify({"error": "Post not found"}), 404
    mongo.db.posts.delete_one({"_id": ObjectId(post_id)})
    return jsonify({"message": "Post deleted successfully"})

@app.route("/api/blogposts/<id>", methods=["DELETE"])
def delete_blog(id):
    try:
        # ✅ Find the post
        blog = mongo.db.blog_posts.find_one({"_id": ObjectId(id)})

        if not blog:
            return jsonify({"message": "Blog not found"}), 404

        # ✅ If post has an image, delete it from the filesystem
        image_path = blog.get("image")
        if image_path:
            # remove leading "/" from "/uploads/filename.jpg"
            full_path = image_path.lstrip("/")
            if os.path.exists(full_path):
                os.remove(full_path)

        # ✅ Delete from MongoDB
        mongo.db.blog_posts.delete_one({"_id": ObjectId(id)})

        return jsonify({"message": "Blog deleted successfully"}), 200

    except Exception as e:
        print("Error deleting blog:", e)
        return jsonify({"message": "Server error", "error": str(e)}), 50
    
    
# ✅ Get paginated blog posts
@app.route("/api/blogpost", methods=["GET"])
def get_blogposts():
    try:
        page = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 12))
        skip = (page - 1) * limit

        total_posts = mongo.db.blog_posts.count_documents({})
        posts_cursor = mongo.db.blog_posts.find().sort("created_at", -1).skip(skip).limit(limit)
        posts = list(posts_cursor)

        # Convert ObjectId to string for frontend
        for post in posts:
            post["_id"] = str(post["_id"])
            # Prepend full URL to image if exists
            if "image" in post and post["image"] and not post["image"].startswith("http"):
                post["image"] = f"http://localhost:5000{post['image']}"

        return jsonify({
            "posts": posts,
            "page": page,
            "limit": limit,
            "totalPages": (total_posts + limit - 1) // limit
        }), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500
    

# --- API Route ---
@app.route("/api/singleblogpost/<slug>", methods=["GET"])
def get_single_blog(slug):
    """
    Fetches a single blog post by its URL slug.
    Also handles converting ObjectId and fetching category details.
    """
    try:
        # 1. Find the blog by slug
        blog = mongo.db.blog_posts.find_one({"slug": slug})
        
        if not blog:
            return jsonify({"message": f"Blog with slug '{slug}' not found"}), 404

        # 2. Convert _id to string for JSON serialization
        blog["_id"] = str(blog["_id"])

        # 3. Prepend base URL to image if it's a relative path
        BASE_URL = "http://localhost:5000"
        if "image" in blog and blog["image"] and not blog["image"].startswith("http"):
            # Assuming 'image' holds the path relative to the static folder (e.g., '/uploads/image.jpg')
            blog["image"] = f"{BASE_URL}{blog['image']}"

        # 4. Fetch category name if category is stored as an ID
        category_id = blog.get("category")
        
        # Check if category_id is a valid ObjectId string or ObjectId object
        if category_id:
            try:
                # Ensure the ID is properly converted if it's a string
                oid = ObjectId(category_id) if isinstance(category_id, str) else category_id
                category = mongo.db.categories.find_one({"_id": oid})
                
                if category:
                    blog["category"] = {"_id": str(category["_id"]), "name": category["name"]}
                else:
                    # ✅ IMPROVEMENT: Set category to None if the associated category document is missing
                    blog["category"] = None
            except Exception:
                # Handles cases where category_id exists but is not a valid ObjectId (corrupt data)
                blog["category"] = None
        else:
            blog["category"] = None

        return jsonify(blog), 200
        
    except Exception as e:
        # Log the error for debugging purposes on the server side
        print(f"Error fetching blog post: {e}")
        return jsonify({"message": "Internal Server Error", "error": str(e)}), 500



DIGITRANSIT_API = "https://api.digitransit.fi/routing/v1/routers/hsl/index/graphql"

@app.route("/api/next-buses", methods=["GET"])
def next_buses():
    stop_id = request.args.get("stop_id", "HSL:1204103")  # Default stop (Kamppi area)
    print("Fetching buses for stop:", stop_id)

    # ✅ GraphQL query for next 10 departures (must use escaped quotes!)
    query = {
        "query": f"""
        {{
          stop(id: "{stop_id}") {{
            name
            stoptimesWithoutPatterns(numberOfDepartures: 10) {{
              scheduledDeparture
              realtimeDeparture
              serviceDay
              trip {{
                routeShortName
                headsign
              }}
            }}
          }}
        }}
        """
    }

    try:
        res = requests.post(
            "https://api.digitransit.fi/routing/v1/routers/hsl/index/graphql",
            json=query,
            headers={"Content-Type": "application/json"}
        )

        # If HSL returns error
        if res.status_code != 200:
            print("HSL API Error:", res.text)
            return jsonify({"error": "HSL API error", "details": res.text}), 400

        data = res.json()

        stop_data = data.get("data", {}).get("stop", None)
        if not stop_data:
            return jsonify({"error": "Stop not found"}), 404

        buses = []
        for st in stop_data["stoptimesWithoutPatterns"]:
            buses.append({
                "route": st["trip"]["routeShortName"],
                "headsign": st["trip"]["headsign"],
                "scheduled": st["scheduledDeparture"],
                "realtime": st["realtimeDeparture"]
            })

        return jsonify({
            "stop_name": stop_data["name"],
            "buses": buses
        })

    except Exception as e:
        print("Error fetching data:", e)
        return jsonify({"error": "Failed to fetch HSL data"}), 500


DIGITRANSIT_API_URL = "https://api.digitransit.fi/routing/v1/routers/hsl/index/graphql"
@app.route("/api/hsl-departures/<stop_id>", methods=["GET"])

def fetch_next_departures(stop_id):
    """
    Fetches the next bus departures for a given HSL stop ID.
    Example HSL stop ID: 'HSL:1234123' (Check the HSL site for correct IDs)
    """
    # 1. Define the GraphQL Query
    query = """
    query StopQuery($id: String!) {
      stop(id: $id) {
        name
        code
        stoptimesWithoutPatterns {
          scheduledDeparture
          realtimeDeparture
          headsign
          trip {
            route {
              shortName
            }
          }
          realtime
        }
      }
    }
    """
    # 2. Define the variables (the stop ID)
    variables = {"id": stop_id}

    # 3. Send the POST request
    response = requests.post(
        DIGITRANSIT_API_URL,
        json={'query': query, 'variables': variables}
    )

    if response.status_code == 200:
        data = response.json()
        # You would typically process and simplify this data before sending it to the React front-end
        return data.get('data', {}).get('stop', {})
    else:
        # Handle error
        return None


# ---------------------------
# Root
# ---------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "API running"}), 200

# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
