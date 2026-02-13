# SECURITY MANIFEST

## 🔒 Secure Storage
All sensitive data (Database, Backups, Transactions) has been moved to:
`./secure_storage/`

This folder is:
1. **Hidden** (System attribute)
2. **Access Controlled** (Only readable by YOU)
3. **Encrypted** (At the application level via Fernet)

## 🔑 Environment Secrets
The `.env` file containing API Keys is **Hidden** and **Access Locked**.

## 🛡️ Best Practices
- Do **NOT** rename or move the `secure_storage` folder manually.
- Use `backup_manager.py` to create backups.
- Use `start_secured.bat` to launch the server securely.

## ⚠️ Warning
Deleting `secure_storage/doudou.db` will erase all user accounts and conversations permanently.
