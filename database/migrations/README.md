# Database Migrations

## How to Apply Migrations

### Via phpMyAdmin:
1. Login to phpMyAdmin
2. Select database `apsx2353_jce-data`
3. Go to SQL tab
4. Copy and paste the SQL from migration file
5. Click "Go" to execute

### Via MySQL Command Line:
```bash
mysql -u apsx2353_jce-data -p apsx2353_jce-data < database/migrations/add_session_keys_table.sql
```

## Available Migrations

### add_session_keys_table.sql
**Date:** 2025-12-13
**Purpose:** Adds `session_keys` table for JWT session management

**What it does:**
- Creates `session_keys` table to store temporary encryption sessions
- Adds indexes for performance
- Creates automatic cleanup event for expired sessions

**Required:** Yes - This table is needed for the authentication system to work

## Note

If you don't run this migration manually, the table will be created automatically when you first call `/api/auth/get-session-key.php`. However, it's recommended to run it manually to ensure proper setup.
