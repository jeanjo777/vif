import sqlite3
import shutil
import os
import datetime
import zipfile
import glob

# Configuration
# Configuration
DB_FILE = os.path.join('secure_storage', 'doudou.db')
BACKUP_DIR = os.path.join('secure_storage', 'backups')
MAX_BACKUPS = 10  # Keep last 10 backups

def ensure_backup_dir():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        print(f"📁 Created backup directory: {BACKUP_DIR}")

def perform_backup():
    ensure_backup_dir()
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    backup_name = f"doudou_backup_{timestamp}.db"
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    zip_path = os.path.join(BACKUP_DIR, f"doudou_backup_{timestamp}.zip")

    try:
        # A. Hot Backup (Safe while server is running)
        print("⏳ Starting database snapshot...")
        
        # Connect to Source and Dest
        src = sqlite3.connect(DB_FILE)
        dst = sqlite3.connect(backup_path)
        
        # Use SQLite Online Backup API
        with dst:
            src.backup(dst)
        
        dst.close()
        src.close()
        print(f"✅ Database snapshot saved: {backup_name}")

        # B. Compress (Zip)
        print("📦 Compressing backup...")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(backup_path, arcname=backup_name)
            # Optional: Add .env key file if you want full recovery (RISKY - keep separate usually)
            # if os.path.exists('.env'):
            #     zipf.write('.env', arcname='.env')
        
        # Cleanup raw .db file after zip
        os.remove(backup_path)
        print(f"🔒 Backup compressed: {zip_path}")
        
        return True

    except Exception as e:
        print(f"❌ Backup Failed: {e}")
        if os.path.exists(backup_path): os.remove(backup_path)
        return False

def rotate_backups():
    print("🔄 Checking retention policy...")
    files = sorted(glob.glob(os.path.join(BACKUP_DIR, "*.zip")), key=os.path.getmtime, reverse=True)
    
    if len(files) > MAX_BACKUPS:
        for f in files[MAX_BACKUPS:]:
            try:
                os.remove(f)
                print(f"🗑️ Removed old backup: {os.path.basename(f)}")
            except OSError as e:
                print(f"⚠️ Error deleting {f}: {e}")
    else:
        print("✅ Retention OK.")

if __name__ == "__main__":
    print("--- DOUDOU BACKUP SYSTEM ---")
    if os.path.exists(DB_FILE):
        if perform_backup():
            rotate_backups()
            print("\n✨ Backup process completed successfully.")
    else:
        print(f"❌ Database file '{DB_FILE}' not found.")
