from sqlalchemy import create_engine, Column, Integer, MetaData, Table, text
from database import SessionLocal, engine
import models

def migrate_password_entries():
    print("Starting database migration...")
    
    # Create a connection
    conn = engine.connect()
    transaction = conn.begin()
    
    try:
        # Check if the column exists
        result = conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name = 'password_entries' AND column_name = 'user_specific_id'"))
        exists = result.fetchone() is not None
        
        if not exists:
            print("Adding 'user_specific_id' column to 'password_entries' table...")
            
            # Execute the SQL to add the column
            conn.execute(text("ALTER TABLE password_entries ADD COLUMN user_specific_id INTEGER"))
            conn.execute(text("CREATE INDEX ix_password_entries_user_specific_id ON password_entries (user_specific_id)"))
            
            # Set default values for existing records
            conn.execute(text("""
                WITH indexed_entries AS (
                    SELECT id, user_id, ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY id) AS row_num
                    FROM password_entries
                )
                UPDATE password_entries
                SET user_specific_id = indexed_entries.row_num
                FROM indexed_entries
                WHERE password_entries.id = indexed_entries.id
            """))
            
            transaction.commit()
            print("Migration completed successfully!")
        else:
            print("Column 'user_specific_id' already exists in 'password_entries' table.")
            transaction.rollback()
    except Exception as e:
        transaction.rollback()
        print(f"Migration failed: {str(e)}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_password_entries() 