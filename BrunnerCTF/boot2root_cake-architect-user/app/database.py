import psycopg2
import psycopg2.pool
import time
import json
from utils import hash_password

# Database configuration
DB_CONFIG = {
    'dbname': 'cake_db',
    'user': 'postgres',
    'password': '871576ad349c9b16620685b58ab569ce',
    'host': 'db',
    'port': 5432
}

db_pool = None

def init_db_pool():
    """Initialize database connection pool"""
    global db_pool
    try:
        db_pool = psycopg2.pool.SimpleConnectionPool(
            minconn=1,
            maxconn=20,
            **DB_CONFIG
        )
        print("Database connection pool initialized successfully")
    except Exception as e:
        print(f"Failed to initialize database pool: {e}")
        db_pool = None

def get_db():
    """Get a database connection from the pool"""
    global db_pool
    if db_pool is None:
        return psycopg2.connect(**DB_CONFIG)
    return db_pool.getconn()

def return_db(conn):
    """Return a database connection to the pool"""
    global db_pool
    if db_pool is not None:
        db_pool.putconn(conn)
    else:
        conn.close()

def wait_for_db():
    """Wait for database to be ready"""
    max_retries = 30
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            conn.close()
            print("Database is ready!")
            return True
        except psycopg2.OperationalError:
            print(f"Database not ready, retrying... ({retry_count + 1}/{max_retries})")
            retry_count += 1
            time.sleep(2)
    
    print("Failed to connect to database after maximum retries")
    return False

def setup_users(admin_pass):
    """Set up initial users in the database"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Create admin user
        admin_password_hash = hash_password(admin_pass)
        cur.execute("""
            INSERT INTO users (username, email, password, role) 
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (username) DO NOTHING
        """, ('admin', 'admin@cakearchitect.com', admin_password_hash, 'admin'))
        
        conn.commit()
        print(f"✅ Admin user created with password: {admin_pass}")
        
    except Exception as e:
        print(f"❌ Error setting up users: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            return_db(conn)

def setup_sample_cakes():
    """Set up sample cakes in the database"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Sample cakes
        cakes = [
            {
                'name': 'Classic Chocolate Cake',
                'ingredients': {"flour": "2 cups", "sugar": "1 cup", "cocoa": "1 cup"},
                'instructions': 'Mix dry ingredients, add wet ingredients, bake at 350F for 30 minutes',
                'created_by': 'admin',
                'is_public': True
            },
            {
                'name': 'Vanilla Sponge Cake',
                'ingredients': {"flour": "1 cup", "sugar": "1 cup", "eggs": "3"},
                'instructions': 'Beat eggs and sugar, fold in flour, bake at 325F for 25 minutes',
                'created_by': 'admin',
                'is_public': True
            }
        ]
        
        for cake in cakes:
            ingredients_json = json.dumps(cake['ingredients'])
            cur.execute("""
                INSERT INTO cakes (name, ingredients, instructions, created_by, is_public) 
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
            """, (cake['name'], ingredients_json, cake['instructions'], cake['created_by'], cake['is_public']))
        
        conn.commit()
        print("✅ Sample cakes created")
        
    except Exception as e:
        print(f"❌ Error setting up cakes: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            return_db(conn)

def get_user_by_credentials(username, password):
    """Get user by username and password"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        hashed_password = hash_password(password)
        cur.execute("SELECT id, username, role FROM users WHERE username = %s AND password = %s", 
                   (username, hashed_password))
        return cur.fetchone()
        
    except Exception as e:
        print(f"Error getting user: {e}")
        return None
    finally:
        if conn:
            return_db(conn)

def create_user(username, email, password, role='user'):
    """Create a new user"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        hashed_password = hash_password(password)
        cur.execute("INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)",
                   (username, email, hashed_password, role))
        conn.commit()
        return True
        
    except Exception as e:
        print(f"Error creating user: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            return_db(conn)

def get_user_cakes(username):
    """Get cakes for a user (their own + public ones)"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, name, created_by FROM cakes WHERE created_by = %s OR is_public = true", 
                   (username,))
        return cur.fetchall()
        
    except Exception as e:
        print(f"Error getting cakes: {e}")
        return []
    finally:
        if conn:
            return_db(conn)

def get_cake_by_id(cake_id):
    """Get a cake by ID"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, name, ingredients, instructions, created_by, is_public FROM cakes WHERE id = %s", (cake_id,))
        return cur.fetchone()
        
    except Exception as e:
        print(f"Error getting cake: {e}")
        return None
    finally:
        if conn:
            return_db(conn)

def save_cake(name, ingredients, instructions, created_by):
    """Save a new cake"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        ingredients_json = json.dumps(ingredients)
        cur.execute("INSERT INTO cakes (name, ingredients, instructions, created_by) VALUES (%s, %s, %s, %s)",
                   (name, ingredients_json, instructions, created_by))
        conn.commit()
        return True
        
    except Exception as e:
        print(f"Error saving cake: {e}")
        return False
    finally:
        if conn:
            return_db(conn)

def get_all_users():
    """Get all users for admin panel"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC")
        return cur.fetchall()
        
    except Exception as e:
        print(f"Error getting users: {e}")
        return []
    finally:
        if conn:
            return_db(conn)

def calculate_nutrition(cake_id):
    """Calculate nutrition for a cake"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()

        query = f"SELECT ingredients FROM cakes WHERE id = {cake_id}"
        cur.execute(query)
        plan = cur.fetchall()
        if not plan:
            return json.dumps({"error": "Cake not found"})

        # Handle both JSON string and already parsed dict
        ingredients_data = plan[0][0]
        if isinstance(ingredients_data, str):
            ingredients = json.loads(ingredients_data)
        else:
            ingredients = ingredients_data  # Already a dict
            
        total = 0
        for ing in ingredients:
            # Extract the quantity from strings like "2 cups", "1 cup", "3"
            quantity_str = ingredients[ing].split(' ')[0]
            try:
                total += int(quantity_str)
            except ValueError:
                # If we can't parse as int, try to extract number from string
                import re
                numbers = re.findall(r'\d+', quantity_str)
                if numbers:
                    total += int(numbers[0])

        return json.dumps({
            "cake_id": cake_id,
            "calculated": {
                "calories": total * 50,
                "fat": total * 2,
                "protein": total * 1.5
            }
        })

    except Exception as e:
        return json.dumps({"error": str(e)})
    finally:
        if conn:
            return_db(conn)
